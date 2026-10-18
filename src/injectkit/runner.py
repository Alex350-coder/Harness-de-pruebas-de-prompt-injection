"""Bounded execution: collect one ``Exchange`` per (payload, run) with hard limits."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from injectkit.config import Limits
from injectkit.errors import InjectKitError, RunPlanError, TargetError
from injectkit.models import Canary, ErrorInfo, ErrorKind, Exchange, Payload, Suite
from injectkit.payloads.canary import new_canary
from injectkit.payloads.render import render
from injectkit.ratelimit import (
    AsyncRateLimiter,
    Attempted,
    Jitter,
    Sleep,
    call_with_retries,
)
from injectkit.redact import Redactor
from injectkit.targets.base import Target, TargetResponse


@dataclass(frozen=True, slots=True)
class RunSettings:
    concurrency: int
    requests_per_second: float
    retries: int
    max_requests: int

    @classmethod
    def from_limits(cls, limits: Limits, *, max_requests: int | None = None) -> RunSettings:
        return cls(
            concurrency=limits.concurrency,
            requests_per_second=limits.requests_per_second,
            retries=limits.retries,
            max_requests=limits.max_requests if max_requests is None else max_requests,
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

    async def _send(self, text: str) -> TargetResponse:
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
