import asyncio

import pytest

from injectkit.errors import TargetError
from injectkit.models import ErrorKind
from injectkit.ratelimit import (
    BACKOFF_CAP_SECONDS,
    RETRY_AFTER_CAP_SECONDS,
    AsyncRateLimiter,
    backoff_delay,
    call_with_retries,
    is_retriable,
)


class FakeClock:
    """Virtual time: ``sleep`` wakes at call-time + delay, never earlier."""

    def __init__(self) -> None:
        self.now = 0.0
        self.wakes: list[float] = []

    def __call__(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        wake = self.now + delay
        await asyncio.sleep(0)
        self.now = max(self.now, wake)
        self.wakes.append(wake)


async def test_concurrent_acquisitions_are_spaced_by_the_minimum_interval() -> None:
    clock = FakeClock()
    limiter = AsyncRateLimiter(4.0, clock=clock, sleep=clock.sleep)
    await asyncio.gather(*(limiter.acquire() for _ in range(6)))
    # the first slot is immediate (no sleep); the rest are 0.25 s apart
    assert clock.wakes == pytest.approx([0.25 * i for i in range(1, 6)])


async def test_idle_limiter_does_not_bank_credit() -> None:
    clock = FakeClock()
    limiter = AsyncRateLimiter(1.0, clock=clock, sleep=clock.sleep)
    await limiter.acquire()
    clock.now = 100.0  # long idle period
    await asyncio.gather(limiter.acquire(), limiter.acquire())
    assert clock.wakes == pytest.approx([101.0])  # only the second waits a full interval


@pytest.mark.parametrize("rps", [0, -1.0])
def test_non_positive_rate_is_rejected(rps: float) -> None:
    with pytest.raises(ValueError, match="requests_per_second"):
        AsyncRateLimiter(rps)


async def test_real_clock_defaults_work() -> None:
    limiter = AsyncRateLimiter(1000.0)
    await asyncio.gather(*(limiter.acquire() for _ in range(3)))


def test_retriable_kinds() -> None:
    assert is_retriable(TargetError(ErrorKind.TIMEOUT, "t"))
    assert is_retriable(TargetError(ErrorKind.CONNECT, "c"))
    for status in (429, 502, 503, 504):
        assert is_retriable(TargetError(ErrorKind.HTTP_STATUS, "s", status_code=status))


@pytest.mark.parametrize(
    "error",
    [
        TargetError(ErrorKind.HTTP_STATUS, "s", status_code=500),
        TargetError(ErrorKind.HTTP_STATUS, "s", status_code=404),
        TargetError(ErrorKind.HTTP_STATUS, "s"),
        TargetError(ErrorKind.MALFORMED_RESPONSE, "m"),
        TargetError(ErrorKind.RESPONSE_TOO_LARGE, "l"),
        TargetError(ErrorKind.POLICY, "p"),
        TargetError(ErrorKind.EXTRACTION, "e"),
        TargetError(ErrorKind.INTERNAL, "i"),
    ],
)
def test_non_retriable_errors(error: TargetError) -> None:
    assert not is_retriable(error)


def test_backoff_is_exponential_capped_and_jittered() -> None:
    full = [backoff_delay(n, None, rng=lambda: 1.0) for n in range(1, 8)]
    assert full[:5] == [0.5, 1.0, 2.0, 4.0, 8.0]
    assert full[5:] == [BACKOFF_CAP_SECONDS, BACKOFF_CAP_SECONDS]
    assert backoff_delay(1, None, rng=lambda: 0.0) == 0.25  # jitter keeps at least half


def test_retry_after_is_honored_but_capped() -> None:
    assert backoff_delay(1, 7.0, rng=lambda: 1.0) == 7.0
    assert backoff_delay(1, 9999.0, rng=lambda: 1.0) == RETRY_AFTER_CAP_SECONDS
    assert backoff_delay(1, -5.0, rng=lambda: 1.0) == 0.5


class Flaky:
    def __init__(self, failures: list[TargetError], result: str = "ok") -> None:
        self.failures = list(failures)
        self.result = result
        self.calls = 0

    async def __call__(self) -> str:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return self.result


async def no_sleep(delay: float) -> None:
    return None


async def test_success_on_first_try_uses_one_attempt() -> None:
    op = Flaky([])
    outcome = await call_with_retries(op, retries=3, sleep=no_sleep)
    assert (outcome.value, outcome.error, outcome.attempts) == ("ok", None, 1)


async def test_transient_failures_are_retried_until_success() -> None:
    op = Flaky([TargetError(ErrorKind.TIMEOUT, "t"), TargetError(ErrorKind.CONNECT, "c")])
    outcome = await call_with_retries(op, retries=2, sleep=no_sleep)
    assert outcome.value == "ok"
    assert outcome.attempts == 3


@pytest.mark.parametrize("retries", [0, 1, 2, 5])
async def test_attempts_never_exceed_retries_plus_one(retries: int) -> None:
    op = Flaky([TargetError(ErrorKind.TIMEOUT, "t")] * 50)
    outcome = await call_with_retries(op, retries=retries, sleep=no_sleep)
    assert op.calls == retries + 1
    assert outcome.attempts == retries + 1
    assert outcome.error is not None
    assert outcome.value is None


async def test_non_retriable_error_is_not_retried() -> None:
    op = Flaky([TargetError(ErrorKind.EXTRACTION, "e")] * 5)
    outcome = await call_with_retries(op, retries=5, sleep=no_sleep)
    assert (op.calls, outcome.attempts) == (1, 1)
    assert outcome.error is not None
    assert outcome.error.kind is ErrorKind.EXTRACTION


async def test_backoff_sleeps_between_attempts_and_honors_retry_after() -> None:
    delays: list[float] = []

    async def record(delay: float) -> None:
        delays.append(delay)

    errors = [
        TargetError(ErrorKind.HTTP_STATUS, "s", status_code=429, retry_after=3.0),
        TargetError(ErrorKind.TIMEOUT, "t"),
    ]
    await call_with_retries(Flaky(errors), retries=2, sleep=record, rng=lambda: 1.0)
    assert delays == [3.0, 1.0]


async def test_unexpected_exceptions_propagate_instead_of_being_swallowed() -> None:
    async def boom() -> str:
        raise ValueError("bug")

    with pytest.raises(ValueError, match="bug"):
        await call_with_retries(boom, retries=3, sleep=no_sleep)


def test_negative_retries_are_rejected() -> None:
    with pytest.raises(ValueError, match="retries"):
        asyncio.run(call_with_retries(Flaky([]), retries=-1, sleep=no_sleep))
