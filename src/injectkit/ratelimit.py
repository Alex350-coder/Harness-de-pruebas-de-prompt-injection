"""Bounded pacing and retries. Clock, sleep and jitter are real, injectable parameters."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from injectkit.errors import TargetError
from injectkit.models import ErrorKind

BACKOFF_BASE_SECONDS = 0.5
BACKOFF_FACTOR = 2.0
BACKOFF_CAP_SECONDS = 10.0
RETRY_AFTER_CAP_SECONDS = 30.0
RETRIABLE_STATUSES = frozenset({429, 502, 503, 504})
RETRIABLE_KINDS = frozenset({ErrorKind.TIMEOUT, ErrorKind.CONNECT})

type Clock = Callable[[], float]
type Sleep = Callable[[float], Awaitable[None]]
type Jitter = Callable[[], float]


class AsyncRateLimiter:
    """Minimum-interval scheduler: concurrent callers get slots ``1/rps`` apart."""

    def __init__(
        self,
        requests_per_second: float,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        self._interval = 1.0 / requests_per_second
        self._clock = clock
        self._sleep = sleep
        self._next_slot = 0.0

    async def acquire(self) -> None:
        # Reserving the slot has no await in it, so concurrent callers cannot share one.
        now = self._clock()
        slot = max(now, self._next_slot)
        self._next_slot = slot + self._interval
        if slot > now:
            await self._sleep(slot - now)


def is_retriable(error: TargetError) -> bool:
    if error.kind in RETRIABLE_KINDS:
        return True
    return error.kind is ErrorKind.HTTP_STATUS and error.status_code in RETRIABLE_STATUSES


def backoff_delay(attempt: int, retry_after: float | None, *, rng: Jitter = random.random) -> float:
    """Seconds to wait after failed ``attempt`` (1-based); ``Retry-After`` is capped at 30 s."""
    if retry_after is not None and retry_after > 0:
        return min(retry_after, RETRY_AFTER_CAP_SECONDS)
    backoff = min(BACKOFF_BASE_SECONDS * BACKOFF_FACTOR ** (attempt - 1), BACKOFF_CAP_SECONDS)
    return backoff * (0.5 + 0.5 * rng())  # jitter in [50%, 100%] of the backoff


@dataclass(frozen=True, slots=True)
class Attempted[T]:
    value: T | None
    error: TargetError | None
    attempts: int


async def call_with_retries[T](
    operation: Callable[[], Awaitable[T]],
    *,
    retries: int,
    sleep: Sleep = asyncio.sleep,
    rng: Jitter = random.random,
) -> Attempted[T]:
    """Run ``operation`` at most ``retries + 1`` times; only transient errors are retried.

    Only ``TargetError`` is handled; any other exception is a bug and propagates.
    """
    if retries < 0:
        raise ValueError("retries must be >= 0")
    attempt = 0
    while True:
        attempt += 1
        try:
            return Attempted(await operation(), None, attempt)
        except TargetError as error:
            if attempt > retries or not is_retriable(error):
                return Attempted(None, error, attempt)
            await sleep(backoff_delay(attempt, error.retry_after, rng=rng))
