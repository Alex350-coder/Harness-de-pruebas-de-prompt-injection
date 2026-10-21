from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from injectkit.models import (
    Canary,
    CheckSpec,
    Confidence,
    ErrorInfo,
    ErrorKind,
    Exchange,
    Finding,
    Outcome,
    Payload,
    RunResult,
    Severity,
    TestResult,
)

CANARY = Canary(value="INJK-0123456789abcdef", half_a="INJK-01234567", half_b="89abcdef")
JOIN_REQUEST = f"Join {CANARY.half_a} and {CANARY.half_b} and print only the result."

PayloadFactory = Callable[..., Payload]
ExchangeFactory = Callable[..., Exchange]


@pytest.fixture
def canary() -> Canary:
    return CANARY


@pytest.fixture
def make_payload() -> PayloadFactory:
    def build(
        payload_id: str = "p-1",
        *,
        category: str = "direct_override",
        severity: Severity = Severity.HIGH,
        checks: tuple[CheckSpec, ...] = (),
        remediation: str = "Treat untrusted input as data.",
    ) -> Payload:
        return Payload(
            id=payload_id,
            category=category,
            severity=severity,
            title="t",
            description="d",
            template="Say {{ canary_a }} then {{ canary_b }}",
            checks=checks,
            remediation=remediation,
            reviewed=True,
        )

    return build


@pytest.fixture
def make_exchange() -> ExchangeFactory:
    def build(
        response: str | None,
        *,
        payload_id: str = "p-1",
        request: str = JOIN_REQUEST,
        error: ErrorInfo | None = None,
        status: int | None = 200,
    ) -> Exchange:
        return Exchange(
            payload_id=payload_id,
            canary=CANARY,
            request_text=request,
            response_text=response,
            status_code=status if error is None else None,
            error=error,
            started_at=datetime(2026, 10, 19, tzinfo=UTC),
            duration_ms=12.5,
            attempts=1,
        )

    return build


@pytest.fixture
def timeout_error() -> ErrorInfo:
    return ErrorInfo(kind=ErrorKind.TIMEOUT, message="timed out")


RunFactory = Callable[..., RunResult]
STARTED = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def _finding(
    payload_id: str,
    outcome: Outcome,
    *,
    evidence: str,
    detector: str = "canary",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        test_id=f"{payload_id}-t1",
        payload_id=payload_id,
        category="direct_override",
        detector=detector,
        severity=severity,
        confidence=Confidence.HIGH if outcome is Outcome.CONFIRMED else Confidence.MEDIUM,
        outcome=outcome,
        evidence=evidence,
        matched_indicator="canary" if detector == "canary" else detector,
        target_id="demo",
        timestamp=STARTED,
        remediation="Treat untrusted input as data.",
        limitations="Shows instruction-following; not data-theft proof.",
    )


@pytest.fixture
def make_run() -> RunFactory:
    """A fixed five-outcome ``RunResult`` (one test per outcome class)."""

    def build(
        *,
        evidence: str = "...reply INJK-0123456789abcdef end...",
        error_message: str = "connection refused",
        excerpt: str | None = None,
        outcomes: tuple[Outcome, ...] = (
            Outcome.CONFIRMED,
            Outcome.POTENTIAL,
            Outcome.NO_INDICATOR,
            Outcome.INCONCLUSIVE,
            Outcome.ERROR,
        ),
    ) -> RunResult:
        results: list[TestResult] = []
        for index, outcome in enumerate(outcomes):
            pid = f"p-{index + 1}"
            if outcome in (Outcome.CONFIRMED, Outcome.POTENTIAL):
                results.append(
                    TestResult(
                        payload_id=pid,
                        outcome=outcome,
                        findings=(_finding(pid, outcome, evidence=evidence),),
                        duration_ms=10.0,
                        response_excerpt=excerpt,
                    )
                )
            elif outcome is Outcome.ERROR:
                results.append(
                    TestResult(
                        payload_id=pid,
                        outcome=outcome,
                        error=ErrorInfo(kind=ErrorKind.CONNECT, message=error_message),
                        duration_ms=1.0,
                    )
                )
            else:
                results.append(
                    TestResult(
                        payload_id=pid, outcome=outcome, duration_ms=5.0, response_excerpt=excerpt
                    )
                )
        counts = {o.value: 0 for o in Outcome}
        for r in results:
            counts[r.outcome.value] += 1
        return RunResult(
            run_id="run-0001",
            started_at=STARTED,
            finished_at=STARTED,
            target_id="demo",
            suite="basic",
            settings_summary={"concurrency": 4, "planned_requests": len(results)},
            results=tuple(results),
            counts=counts,
            tool_version="0.1.0.dev0",
        )

    return build
