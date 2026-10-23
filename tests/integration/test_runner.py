import asyncio
from collections.abc import Callable
from types import TracebackType
from typing import Self

import httpx
import pytest
import respx

from injectkit.config import ResolvedTarget, parse_config, resolve_config
from injectkit.errors import RunPlanError, TargetError
from injectkit.models import ErrorKind, Payload, Severity, Suite
from injectkit.ratelimit import AsyncRateLimiter
from injectkit.redact import Redactor
from injectkit.runner import RunSettings, collect_exchanges
from injectkit.targets.base import TargetResponse
from injectkit.targets.http import HttpTarget

URL = "https://api.example.test/chat"


def make_payload(pid: str, template: str = "Say {{ canary_a }} then {{ canary_b }}") -> Payload:
    return Payload(
        id=pid,
        category="canary",
        severity=Severity.LOW,
        title=pid,
        description="d",
        template=template,
        remediation="r",
    )


def make_suite(count: int, runs: int = 1, template: str | None = None) -> Suite:
    payloads = tuple(
        make_payload(f"p{i}", template) if template else make_payload(f"p{i}") for i in range(count)
    )
    return Suite(version=1, name="s", runs_per_payload=runs, payloads=payloads)


def settings(
    *,
    concurrency: int = 3,
    requests_per_second: float = 1000.0,
    retries: int = 0,
    max_requests: int = 500,
    max_attempts: int = 1000,
) -> RunSettings:
    return RunSettings(
        concurrency=concurrency,
        requests_per_second=requests_per_second,
        retries=retries,
        max_requests=max_requests,
        max_attempts=max_attempts,
    )


async def no_sleep(delay: float) -> None:
    return None


class ScriptedTarget:
    """Test double implementing the Target protocol with a per-call behavior hook."""

    def __init__(self, behavior: Callable[[str, int], str | Exception] | None = None) -> None:
        self.behavior = behavior or (lambda text, n: "reply")
        self.sent: list[str] = []
        self.entered = 0
        self.exited = 0

    async def __aenter__(self) -> Self:
        self.entered += 1
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.exited += 1

    async def send(self, text: str) -> TargetResponse:
        self.sent.append(text)
        outcome = self.behavior(text, len(self.sent))
        if isinstance(outcome, Exception):
            raise outcome
        return TargetResponse(text=outcome, status_code=200)


def http_resolved() -> ResolvedTarget:
    config = parse_config(
        {
            "version": 1,
            "authorization": {"confirmed": True, "scope_note": "tests"},
            "name": "t",
            "request": {"url": URL, "body": {"m": "{{payload}}"}},
            "response": {"path": "reply"},
        }
    )
    return resolve_config(config, {})


async def public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


@respx.mock
async def test_in_flight_requests_never_exceed_the_concurrency_limit() -> None:
    in_flight = 0
    peak = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.005)
        in_flight -= 1
        return httpx.Response(200, json={"reply": "ok"})

    route = respx.post(URL).mock(side_effect=handler)
    resolved = http_resolved()
    target = HttpTarget(resolved, resolver=public_resolver)
    collected = await collect_exchanges(
        target, make_suite(50), settings(concurrency=3), redactor=resolved.redactor
    )
    assert route.call_count == 50
    assert len(collected.exchanges) == 50
    assert all(e.error is None for e in collected.exchanges)
    assert 1 <= peak <= 3
    assert not collected.interrupted


async def test_plan_over_the_request_cap_is_refused_before_any_send() -> None:
    target = ScriptedTarget()
    with pytest.raises(RunPlanError, match="max_requests"):
        await collect_exchanges(
            target, make_suite(10), settings(max_requests=9), redactor=Redactor()
        )
    assert target.sent == []
    assert target.entered == 0


async def test_runs_per_payload_multiplies_the_planned_total() -> None:
    target = ScriptedTarget()
    with pytest.raises(RunPlanError):
        await collect_exchanges(
            target, make_suite(4, runs=2), settings(max_requests=7), redactor=Redactor()
        )
    assert target.sent == []
    collected = await collect_exchanges(
        target, make_suite(4, runs=2), settings(max_requests=8), redactor=Redactor()
    )
    assert len(collected.exchanges) == 8


async def test_each_run_gets_its_own_canary_and_the_value_is_never_sent() -> None:
    target = ScriptedTarget()
    collected = await collect_exchanges(
        target, make_suite(5, runs=3), settings(), redactor=Redactor()
    )
    canaries = {e.canary.value for e in collected.exchanges}
    assert len(canaries) == 15
    for exchange in collected.exchanges:
        assert exchange.canary.value not in exchange.request_text
        assert exchange.canary.half_a in exchange.request_text
    assert all(canary not in text for canary in canaries for text in target.sent)


async def test_one_failing_payload_does_not_affect_the_others() -> None:
    def behavior(text: str, n: int) -> str | Exception:
        if text.startswith("BAD"):
            return TargetError(ErrorKind.EXTRACTION, "no such path")
        return "fine"

    suite = Suite(
        version=1,
        name="s",
        payloads=(
            make_payload("good-1"),
            make_payload("bad", "BAD {{ canary_a }}"),
            make_payload("good-2"),
        ),
    )
    collected = await collect_exchanges(
        ScriptedTarget(behavior), suite, settings(), redactor=Redactor()
    )
    by_id = {e.payload_id: e for e in collected.exchanges}
    assert by_id["bad"].error is not None
    assert by_id["bad"].error.kind is ErrorKind.EXTRACTION
    assert by_id["bad"].response_text is None
    assert by_id["good-1"].response_text == "fine"
    assert by_id["good-2"].error is None


async def test_results_keep_suite_order() -> None:
    collected = await collect_exchanges(
        ScriptedTarget(), make_suite(12), settings(concurrency=5), redactor=Redactor()
    )
    assert [e.payload_id for e in collected.exchanges] == [f"p{i}" for i in range(12)]


async def test_unexpected_exception_becomes_an_internal_error_result() -> None:
    def behavior(text: str, n: int) -> str | Exception:
        return RuntimeError("boom") if n == 2 else "ok"

    collected = await collect_exchanges(
        ScriptedTarget(behavior), make_suite(4), settings(concurrency=1), redactor=Redactor()
    )
    errors = [e for e in collected.exchanges if e.error is not None]
    assert len(errors) == 1
    assert errors[0].error is not None
    assert errors[0].error.kind is ErrorKind.INTERNAL
    assert "RuntimeError" in errors[0].error.message
    assert len(collected.exchanges) == 4


async def test_transient_errors_are_retried_and_attempts_recorded() -> None:
    def behavior(text: str, n: int) -> str | Exception:
        return TargetError(ErrorKind.TIMEOUT, "slow") if n <= 2 else "finally"

    collected = await collect_exchanges(
        ScriptedTarget(behavior),
        make_suite(1),
        settings(retries=2),
        redactor=Redactor(),
        sleep=no_sleep,
    )
    exchange = collected.exchanges[0]
    assert exchange.attempts == 3
    assert exchange.response_text == "finally"
    assert exchange.error is None


async def test_exhausted_retries_report_the_last_error_and_attempts() -> None:
    target = ScriptedTarget(lambda text, n: TargetError(ErrorKind.CONNECT, "down"))
    collected = await collect_exchanges(
        target, make_suite(1), settings(retries=2), redactor=Redactor(), sleep=no_sleep
    )
    assert len(target.sent) == 3
    assert collected.exchanges[0].attempts == 3
    assert collected.exchanges[0].error is not None


async def test_every_attempt_passes_through_the_rate_limiter() -> None:
    acquisitions = 0

    class CountingLimiter(AsyncRateLimiter):
        async def acquire(self) -> None:
            nonlocal acquisitions
            acquisitions += 1

    target = ScriptedTarget(lambda text, n: TargetError(ErrorKind.TIMEOUT, "t"))
    await collect_exchanges(
        target,
        make_suite(2),
        settings(retries=1, concurrency=1),
        redactor=Redactor(),
        limiter=CountingLimiter(1000.0),
        sleep=no_sleep,
    )
    assert acquisitions == 4


async def test_request_text_is_redacted_but_response_text_is_kept_raw() -> None:
    redactor = Redactor()
    redactor.add("topsecret-value", label="frag")
    suite = make_suite(1, template="leak topsecret-value {{ canary_a }}")
    target = ScriptedTarget(lambda text, n: "the topsecret-value is here")
    collected = await collect_exchanges(target, suite, settings(), redactor=redactor)
    exchange = collected.exchanges[0]
    assert "topsecret-value" not in exchange.request_text
    assert "[REDACTED:frag]" in exchange.request_text
    assert exchange.response_text == "the topsecret-value is here"  # detectors need raw text


async def test_target_lifecycle_is_owned_by_the_runner() -> None:
    target = ScriptedTarget()
    await collect_exchanges(target, make_suite(2), settings(), redactor=Redactor())
    assert (target.entered, target.exited) == (1, 1)


async def test_exchange_metadata_is_populated() -> None:
    collected = await collect_exchanges(
        ScriptedTarget(), make_suite(1), settings(), redactor=Redactor()
    )
    exchange = collected.exchanges[0]
    assert exchange.started_at.tzinfo is not None
    assert exchange.duration_ms >= 0
    assert exchange.status_code == 200
    assert exchange.attempts == 1


async def test_cancellation_returns_partial_results_flagged_interrupted() -> None:
    gate = asyncio.Event()

    class SlowTarget(ScriptedTarget):
        async def send(self, text: str) -> TargetResponse:
            self.sent.append(text)
            if len(self.sent) > 2:
                gate.set()
                await asyncio.sleep(30)
            return TargetResponse(text="ok", status_code=200)

    task = asyncio.create_task(
        collect_exchanges(
            SlowTarget(), make_suite(10), settings(concurrency=1), redactor=Redactor()
        )
    )
    await gate.wait()
    task.cancel()
    collected = await task
    assert collected.interrupted
    assert 2 <= len(collected.exchanges) < 10
    assert all(e.error is None for e in collected.exchanges)


def timeout_error(_text: str, _n: int) -> Exception:
    return TargetError(ErrorKind.TIMEOUT, "timed out")


async def test_attempt_budget_caps_total_sends_including_retries() -> None:
    target = ScriptedTarget(timeout_error)
    collected = await collect_exchanges(
        target,
        make_suite(5),
        settings(concurrency=1, retries=2, max_attempts=6),
        redactor=Redactor(),
        sleep=no_sleep,
    )
    assert len(target.sent) == 6  # 3 attempts for each of the first two tests, then stop
    assert len(collected.exchanges) == 5
    assert [e.attempts for e in collected.exchanges] == [3, 3, 1, 1, 1]


async def test_tests_beyond_the_attempt_budget_fail_as_policy_errors_without_sending() -> None:
    target = ScriptedTarget(timeout_error)
    collected = await collect_exchanges(
        target,
        make_suite(5),
        settings(concurrency=1, retries=2, max_attempts=6),
        redactor=Redactor(),
        sleep=no_sleep,
    )
    errors = [e.error for e in collected.exchanges if e.error is not None]
    assert len(errors) == 5
    policy = [e for e in errors if e.kind is ErrorKind.POLICY]
    assert len(policy) == 3, "tests past the budget must be reported as policy errors"
    assert all("attempt budget" in e.message for e in policy)


async def test_budget_is_not_touched_by_a_healthy_run() -> None:
    target = ScriptedTarget()
    collected = await collect_exchanges(
        target, make_suite(10), settings(max_attempts=10), redactor=Redactor()
    )
    assert len(target.sent) == 10
    assert all(e.error is None for e in collected.exchanges)


async def test_plan_larger_than_the_attempt_budget_is_refused_before_any_send() -> None:
    target = ScriptedTarget()
    with pytest.raises(RunPlanError, match="max_attempts"):
        await collect_exchanges(
            target, make_suite(10), settings(max_requests=500, max_attempts=9), redactor=Redactor()
        )
    assert target.sent == []
    assert target.entered == 0


async def test_attempt_budget_holds_under_concurrency() -> None:
    target = ScriptedTarget(timeout_error)
    await collect_exchanges(
        target,
        make_suite(40),
        settings(concurrency=8, retries=3, max_attempts=50),
        redactor=Redactor(),
        sleep=no_sleep,
    )
    assert len(target.sent) == 50
