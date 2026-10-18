from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from injectkit.errors import (
    ConfigError,
    InjectKitError,
    NetworkPolicyError,
    PayloadError,
    ReportError,
    TargetError,
)
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

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def make_finding(**overrides: Any) -> Finding:
    data: dict[str, Any] = {
        "test_id": "t-1",
        "payload_id": "p-1",
        "category": "canary",
        "detector": "canary",
        "severity": Severity.HIGH,
        "confidence": Confidence.HIGH,
        "outcome": Outcome.CONFIRMED,
        "evidence": "response contained the canary",
        "matched_indicator": "canary",
        "target_id": "demo",
        "timestamp": NOW,
        "remediation": "Treat model output as untrusted.",
        "limitations": "Shows instruction-following only.",
    }
    data.update(overrides)
    return Finding(**data)


def make_payload(**overrides: Any) -> Payload:
    data: dict[str, Any] = {
        "id": "p-1",
        "category": "canary",
        "severity": Severity.MEDIUM,
        "title": "Emit canary",
        "description": "Ask the model to emit the canary.",
        "template": "Join {{canary_a}} and {{canary_b}}",
        "checks": [],
        "remediation": "Isolate untrusted input.",
        "reviewed": True,
        "tags": ["basic"],
    }
    data.update(overrides)
    return Payload(**data)


def test_finding_round_trips_through_json() -> None:
    finding = make_finding()
    assert Finding.model_validate_json(finding.model_dump_json()) == finding


def test_models_are_frozen() -> None:
    finding = make_finding()
    with pytest.raises(ValidationError):
        finding.__setattr__("evidence", "changed")


def test_models_forbid_extra_fields() -> None:
    with pytest.raises(ValidationError):
        make_finding(unexpected="x")


@pytest.mark.parametrize("outcome", [Outcome.INCONCLUSIVE, Outcome.NO_INDICATOR, Outcome.ERROR])
def test_finding_rejects_non_finding_outcomes(outcome: Outcome) -> None:
    with pytest.raises(ValidationError):
        make_finding(outcome=outcome)


def test_finding_accepts_potential() -> None:
    assert make_finding(outcome=Outcome.POTENTIAL).outcome is Outcome.POTENTIAL


def test_finding_evidence_is_capped_at_300_chars() -> None:
    assert make_finding(evidence="a" * 300)
    with pytest.raises(ValidationError):
        make_finding(evidence="a" * 301)


def test_canary_halves_must_concatenate_to_value() -> None:
    assert Canary(value="INJK-abcd", half_a="INJK-", half_b="abcd")
    with pytest.raises(ValidationError):
        Canary(value="INJK-abcd", half_a="INJK-", half_b="zzzz")


def test_payload_requires_non_empty_id() -> None:
    with pytest.raises(ValidationError):
        make_payload(id="")


def test_check_spec_rejects_unknown_kind_and_long_pattern() -> None:
    assert CheckSpec(kind="contains", pattern="abc")
    with pytest.raises(ValidationError):
        CheckSpec.model_validate({"kind": "exec", "pattern": "abc"})
    with pytest.raises(ValidationError):
        CheckSpec(kind="regex", pattern="a" * 201)


def test_exchange_with_error_has_no_response() -> None:
    canary = Canary(value="INJK-ab", half_a="INJK", half_b="-ab")
    error = ErrorInfo(kind=ErrorKind.TIMEOUT, message="timed out")
    exchange = Exchange(
        payload_id="p-1",
        canary=canary,
        request_text="hi",
        response_text=None,
        status_code=None,
        error=error,
        started_at=NOW,
        duration_ms=1.5,
        attempts=3,
    )
    assert exchange.error is not None
    assert exchange.response_text is None


def test_exchange_attempts_must_be_positive() -> None:
    canary = Canary(value="INJK-ab", half_a="INJK", half_b="-ab")
    with pytest.raises(ValidationError):
        Exchange(
            payload_id="p-1",
            canary=canary,
            request_text="hi",
            response_text="ok",
            status_code=200,
            error=None,
            started_at=NOW,
            duration_ms=1.0,
            attempts=0,
        )


def test_test_result_error_outcome_requires_error_info() -> None:
    with pytest.raises(ValidationError):
        TestResult(payload_id="p-1", outcome=Outcome.ERROR, duration_ms=1.0)
    result = TestResult(
        payload_id="p-1",
        outcome=Outcome.ERROR,
        error=ErrorInfo(kind=ErrorKind.CONNECT, message="refused"),
        duration_ms=1.0,
    )
    assert result.findings == ()


def test_test_result_findings_only_for_confirmed_or_potential() -> None:
    with pytest.raises(ValidationError):
        TestResult(
            payload_id="p-1",
            outcome=Outcome.NO_INDICATOR,
            findings=[make_finding()],
            duration_ms=1.0,
        )
    ok = TestResult(
        payload_id="p-1",
        outcome=Outcome.CONFIRMED,
        findings=[make_finding()],
        duration_ms=1.0,
    )
    assert len(ok.findings) == 1


def test_run_result_round_trips() -> None:
    run = RunResult(
        run_id="r-1",
        started_at=NOW,
        finished_at=NOW,
        target_id="demo",
        suite="basic",
        settings_summary={"concurrency": 4},
        results=[],
        counts={"confirmed": 0},
        tool_version="0.1.0",
    )
    assert RunResult.model_validate_json(run.model_dump_json()) == run
    assert run.interrupted is False


def test_error_hierarchy() -> None:
    for exc_type in (ConfigError, PayloadError, NetworkPolicyError, ReportError):
        assert issubclass(exc_type, InjectKitError)
    err = TargetError(ErrorKind.TIMEOUT, "slow")
    assert isinstance(err, InjectKitError)
    assert err.kind is ErrorKind.TIMEOUT
    assert str(err) == "slow"
