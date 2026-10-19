from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from injectkit.models import (
    Canary,
    CheckSpec,
    ErrorInfo,
    ErrorKind,
    Exchange,
    Payload,
    Severity,
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
