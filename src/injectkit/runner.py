"""Bounded execution: collect one ``Exchange`` per (payload, run) with hard limits."""

from __future__ import annotations

import asyncio
import random
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from injectkit import __version__
from injectkit.config import DEFAULT_MAX_ATTEMPTS, Limits
from injectkit.detectors import Detector, evaluate
from injectkit.errors import InjectKitError, RunPlanError, TargetError
from injectkit.models import (
    MAX_RESPONSE_EXCERPT_CHARS,
    Canary,
    ErrorInfo,
    ErrorKind,
    Exchange,
    Outcome,
    Payload,
    RunResult,
    Suite,
    TestResult,
)
from injectkit.payloads.canary import new_canary
from injectkit.payloads.render import render
from injectkit.ratelimit import (
    AsyncRateLimiter,
    Attempted,
    Jitter,
    Sleep,
    call_with_retries,
)
from injectkit.redact import Redactor, strip_control
from injectkit.targets.base import Target, TargetResponse


@dataclass(frozen=True, slots=True)
class RunSettings:
    concurrency: int
    requests_per_second: float
    retries: int
    max_requests: int
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    @classmethod
    def from_limits(cls, limits: Limits, *, max_requests: int | None = None) -> RunSettings:
        return cls(
            concurrency=limits.concurrency,
            requests_per_second=limits.requests_per_second,
            retries=limits.retries,
            max_requests=limits.max_requests if max_requests is None else max_requests,
            max_attempts=limits.max_attempts,
        )


@dataclass(frozen=True, slots=True)
class Collected:
    exchanges: tuple[Exchange, ...]
    interrupted: bool


def planned_requests(suite: Suite) -> int:
    return len(suite.payloads) * suite.runs_per_payload


def check_plan(suite: Suite, settings: RunSettings) -> int:
    """Return the planned request count, or raise ``RunPlanError`` if it exceeds the cap."""
    total = planned_requests(suite)
    if total > settings.max_requests:
        raise RunPlanError(
            f"planned {total} requests exceeds max_requests={settings.max_requests}; "
            "nothing was sent"
        )
    if total > settings.max_attempts:
        raise RunPlanError(
            f"planned {total} requests exceeds max_attempts={settings.max_attempts}; "
            "nothing was sent"
        )
    return total


def _error_info(kind: ErrorKind, message: str) -> ErrorInfo:
    return ErrorInfo(kind=kind, message=message)


class _Job:
    """One payload run: render, send with rate limit and retries, build the ``Exchange``."""

    def __init__(
        self,
        target: Target,
        settings: RunSettings,
        redactor: Redactor,
        limiter: AsyncRateLimiter,
        sleep: Sleep,
        rng: Jitter,
    ) -> None:
        self._target = target
        self._settings = settings
        self._redactor = redactor
        self._limiter = limiter
        self._sleep = sleep
        self._rng = rng
        self._attempts_used = 0

    async def _send(self, text: str) -> TargetResponse:
        # No await between the check and the increment, so concurrent jobs cannot overshoot.
        if self._attempts_used >= self._settings.max_attempts:
            raise TargetError(
                ErrorKind.POLICY,
                f"attempt budget of {self._settings.max_attempts} exhausted; nothing more was sent",
            )
        self._attempts_used += 1
        await self._limiter.acquire()
        return await self._target.send(text)

    async def run(self, payload: Payload) -> Exchange:
        started_at = datetime.now(UTC)
        began = time.perf_counter()
        canary = new_canary()
        try:
            request_text = render(payload, canary)
        except InjectKitError as exc:
            return self._build(payload, canary, "", started_at, began, 1, None, exc)
        try:
            outcome: Attempted[TargetResponse] = await call_with_retries(
                lambda: self._send(request_text),
                retries=self._settings.retries,
                sleep=self._sleep,
                rng=self._rng,
            )
        except Exception as exc:  # converted to a typed INTERNAL result, never swallowed
            return self._build(payload, canary, request_text, started_at, began, 1, None, exc)
        return self._build(
            payload, canary, request_text, started_at, began, outcome.attempts, outcome, None
        )

    def _build(
        self,
        payload: Payload,
        canary: Canary,
        request_text: str,
        started_at: datetime,
        began: float,
        attempts: int,
        outcome: Attempted[TargetResponse] | None,
        crash: Exception | None,
    ) -> Exchange:
        error: ErrorInfo | None = None
        response: TargetResponse | None = None
        if crash is not None:
            kind = ErrorKind.INTERNAL
            error = _error_info(kind, self._redactor.mask_exception(crash))
        elif outcome is not None and outcome.error is not None:
            failure: TargetError = outcome.error
            error = _error_info(failure.kind, self._redactor.mask(str(failure)))
        elif outcome is not None:
            response = outcome.value
        return Exchange(
            payload_id=payload.id,
            canary=canary,
            request_text=self._redactor.mask(request_text),
            response_text=None if response is None else response.text,
            status_code=None if response is None else response.status_code,
            error=error,
            started_at=started_at,
            duration_ms=(time.perf_counter() - began) * 1000,
            attempts=attempts,
        )


async def collect_exchanges(
    target: Target,
    suite: Suite,
    settings: RunSettings,
    *,
    redactor: Redactor,
    limiter: AsyncRateLimiter | None = None,
    sleep: Sleep = asyncio.sleep,
    rng: Jitter = random.random,
) -> Collected:
    """Run every payload ``runs_per_payload`` times with bounded concurrency.

    The request cap is checked before anything is sent. Cancelling the call (for example
    on Ctrl+C) returns the exchanges finished so far with ``interrupted=True``.
    """
    check_plan(suite, settings)
    pacer = limiter or AsyncRateLimiter(settings.requests_per_second)
    job = _Job(target, settings, redactor, pacer, sleep, rng)
    work = [payload for payload in suite.payloads for _ in range(suite.runs_per_payload)]
    results: dict[int, Exchange] = {}
    semaphore = asyncio.Semaphore(settings.concurrency)

    async def guarded(index: int, payload: Payload) -> None:
        async with semaphore:
            results[index] = await job.run(payload)

    interrupted = False
    async with target:
        try:
            async with asyncio.TaskGroup() as group:
                for index, payload in enumerate(work):
                    group.create_task(guarded(index, payload))
        except asyncio.CancelledError:
            interrupted = True
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
    return Collected(tuple(results[i] for i in sorted(results)), interrupted)


def _with_excerpt(
    result: TestResult, exchange: Exchange, redactor: Redactor, include: bool
) -> TestResult:
    if not include or exchange.response_text is None:
        return result
    cleaned = strip_control(redactor.mask(strip_control(exchange.response_text)))
    excerpt = cleaned[:MAX_RESPONSE_EXCERPT_CHARS]
    return result.model_copy(
        update={"response_excerpt": excerpt, "response_truncated": len(cleaned) > len(excerpt)}
    )


async def run_suite(
    target: Target,
    suite: Suite,
    settings: RunSettings,
    detectors: Sequence[Detector],
    *,
    redactor: Redactor,
    target_id: str,
    limiter: AsyncRateLimiter | None = None,
    sleep: Sleep = asyncio.sleep,
    rng: Jitter = random.random,
    include_responses: bool = False,
) -> RunResult:
    """The full pipeline: canary -> render -> send -> evaluate, one fresh canary per test.

    With ``include_responses`` each result also carries a redacted, truncated response excerpt.
    """
    started_at = datetime.now(UTC)
    planned = check_plan(suite, settings)
    collected = await collect_exchanges(
        target, suite, settings, redactor=redactor, limiter=limiter, sleep=sleep, rng=rng
    )
    payloads = {payload.id: payload for payload in suite.payloads}
    results = tuple(
        _with_excerpt(
            evaluate(exchange, payloads[exchange.payload_id], detectors),
            exchange,
            redactor,
            include_responses,
        )
        for exchange in collected.exchanges
    )
    counts = {outcome.value: 0 for outcome in Outcome}
    for result in results:
        counts[result.outcome.value] += 1
    return RunResult(
        run_id=uuid.uuid4().hex,
        started_at=started_at,
        finished_at=datetime.now(UTC),
        target_id=target_id,
        suite=suite.name,
        settings_summary={
            "concurrency": settings.concurrency,
            "requests_per_second": settings.requests_per_second,
            "retries": settings.retries,
            "max_requests": settings.max_requests,
            "runs_per_payload": suite.runs_per_payload,
            "planned_requests": planned,
        },
        results=results,
        counts=counts,
        tool_version=__version__,
        interrupted=collected.interrupted,
    )
