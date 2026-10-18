"""Typed exception hierarchy. Messages must already be redacted by callers."""

from injectkit.models import ErrorKind


class InjectKitError(Exception):
    """Base class for every error raised deliberately by InjectKit."""


class ConfigError(InjectKitError):
    """Invalid or unsafe target configuration."""


class PayloadError(InjectKitError):
    """Invalid or unsafe payload/suite definition."""


class NetworkPolicyError(InjectKitError):
    """A URL or address is rejected by the network policy."""


class TargetError(InjectKitError):
    """A request to the target failed; ``kind`` classifies the failure."""

    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        status_code: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code
        self.retry_after = retry_after


class RunPlanError(InjectKitError):
    """The planned run is invalid or exceeds a hard limit; nothing was sent."""


class ReportError(InjectKitError):
    """A report could not be produced or written."""
