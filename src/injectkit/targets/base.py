"""Target protocol: anything that can deliver one payload text and return the reply text."""

from __future__ import annotations

from dataclasses import dataclass
from types import TracebackType
from typing import Protocol, Self


@dataclass(frozen=True, slots=True)
class TargetResponse:
    text: str
    status_code: int


class Target(Protocol):
    """Async context manager owned by the runner; ``send`` makes a single attempt.

    Failures raise ``TargetError`` (with a redacted message); retries are the runner's job.
    """

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def send(self, text: str) -> TargetResponse: ...
