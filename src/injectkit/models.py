"""Core data types. Frozen, strict, no I/O (single source of truth)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_EVIDENCE_CHARS = 300
MAX_CHECK_PATTERN_CHARS = 200
MAX_RESPONSE_EXCERPT_CHARS = 2048


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Outcome(StrEnum):
    CONFIRMED = "confirmed"  # deterministic unique indicator
    POTENTIAL = "potential"  # heuristic match
    INCONCLUSIVE = "inconclusive"  # response received, but not evidence of safety
    NO_INDICATOR = "no_indicator"  # checks ran, nothing matched (NOT proof of safety)
    ERROR = "error"  # transport/config/execution failure, no verdict


FINDING_OUTCOMES = frozenset({Outcome.CONFIRMED, Outcome.POTENTIAL})


class ErrorKind(StrEnum):
    TIMEOUT = "timeout"
    CONNECT = "connect"
    HTTP_STATUS = "http_status"
    MALFORMED_RESPONSE = "malformed_response"
    RESPONSE_TOO_LARGE = "response_too_large"
    POLICY = "policy"
    EXTRACTION = "extraction"
    INTERNAL = "internal"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class CheckSpec(_Model):
    kind: Literal["contains", "regex", "must_contain"]
    pattern: str = Field(min_length=1, max_length=MAX_CHECK_PATTERN_CHARS)


class Payload(_Model):
    id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    severity: Severity
    title: str = Field(min_length=1)
    description: str
    template: str
    checks: tuple[CheckSpec, ...] = ()
    remediation: str
    reviewed: bool = False
    tags: tuple[str, ...] = ()


class Canary(_Model):
    value: str = Field(min_length=1)
    half_a: str = Field(min_length=1)
    half_b: str = Field(min_length=1)

    @model_validator(mode="after")
    def _halves_form_value(self) -> Self:
        if self.half_a + self.half_b != self.value:
            raise ValueError("canary halves must concatenate to the canary value")
        return self


class ErrorInfo(_Model):
    kind: ErrorKind
    message: str


class Exchange(_Model):
    payload_id: str
    canary: Canary
    request_text: str  # already redacted
    response_text: str | None = Field(repr=False)  # raw and unmasked: never shown in a repr
    status_code: int | None
    error: ErrorInfo | None
    started_at: datetime
    duration_ms: float = Field(ge=0)
    attempts: int = Field(ge=1)


class Finding(_Model):
    test_id: str
    payload_id: str
    category: str
    detector: str
    severity: Severity
    confidence: Confidence
    outcome: Outcome
    evidence: str = Field(max_length=MAX_EVIDENCE_CHARS)
    matched_indicator: str
    target_id: str
    timestamp: datetime
    remediation: str
    limitations: str

    @model_validator(mode="after")
    def _outcome_is_a_finding(self) -> Self:
        if self.outcome not in FINDING_OUTCOMES:
            raise ValueError("a Finding must have outcome CONFIRMED or POTENTIAL")
        return self


class TestResult(_Model):
    __test__: ClassVar[bool] = False  # not a pytest class

    payload_id: str
    outcome: Outcome
    findings: tuple[Finding, ...] = ()
    error: ErrorInfo | None = None
    duration_ms: float = Field(ge=0)
    # Redacted, control-stripped response text; only filled when the caller asks for it.
    response_excerpt: str | None = Field(default=None, max_length=MAX_RESPONSE_EXCERPT_CHARS)
    response_truncated: bool = False

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if (self.outcome is Outcome.ERROR) != (self.error is not None):
            raise ValueError("error info is required for, and only for, outcome ERROR")
        if self.findings and self.outcome not in FINDING_OUTCOMES:
            raise ValueError("findings are only allowed for CONFIRMED or POTENTIAL results")
        return self


class RunResult(_Model):
    run_id: str
    started_at: datetime
    finished_at: datetime
    target_id: str
    suite: str
    settings_summary: dict[str, str | int | float | bool]
    results: tuple[TestResult, ...]
    counts: dict[str, int]
    tool_version: str
    interrupted: bool = False


class Suite(_Model):
    version: Literal[1]
    name: str = Field(min_length=1, max_length=100)
    runs_per_payload: int = Field(default=1, ge=1, le=5)
    payloads: tuple[Payload, ...] = Field(min_length=1, max_length=200)
