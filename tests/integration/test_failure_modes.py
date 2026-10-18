"""End-to-end failure matrix: HttpTarget + runner + retries + limiter against respx."""

import itertools
import time
from typing import Any

import httpx
import respx

from injectkit.config import ResolvedTarget, parse_config, resolve_config
from injectkit.models import ErrorKind, Exchange, Payload, Severity, Suite
from injectkit.ratelimit import RETRY_AFTER_CAP_SECONDS, AsyncRateLimiter
from injectkit.runner import RunSettings, collect_exchanges
from injectkit.targets.http import HttpTarget

URL = "https://api.example.test/chat"
API_KEY = "sk-matrix-key-987654"
FOLLOW = {"follow_redirects": True, "max_redirects": 3}


async def public_resolver(host: str, port: int) -> list[str]:
    return ["93.184.216.34"]


def make_resolved(
    *, network: dict[str, Any] | None = None, max_bytes: int = 1024 * 1024
) -> ResolvedTarget:
    config = parse_config(
        {
            "version": 1,
            "authorization": {"confirmed": True, "scope_note": "tests"},
            "name": "matrix",
            "request": {
                "url": URL,
                "headers": {"Authorization": "Bearer ${MATRIX_KEY}"},
                "body": {"messages": [{"role": "user", "content": "{{payload}}"}]},
            },
            "response": {"path": "reply", "max_bytes": max_bytes},
            "network": network or {},
        }
    )
    return resolve_config(config, {"MATRIX_KEY": API_KEY})


def make_suite(count: int = 1) -> Suite:
    payloads = tuple(
        Payload(
            id=f"p{i}",
            category="canary",
            severity=Severity.LOW,
            title="t",
            description="d",
            template="Say {{ canary_a }} then {{ canary_b }}",
            remediation="r",
        )
        for i in range(count)
    )
    return Suite(version=1, name="matrix", payloads=payloads)


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


async def run_one(
    resolved: ResolvedTarget,
    *,
    retries: int = 0,
    count: int = 1,
    recorder: SleepRecorder | None = None,
) -> list[Exchange]:
    settings = RunSettings(
        concurrency=count, requests_per_second=1000.0, retries=retries, max_requests=500
    )
    collected = await collect_exchanges(
        HttpTarget(resolved, resolver=public_resolver),
        make_suite(count),
        settings,
        redactor=resolved.redactor,
        sleep=recorder or SleepRecorder(),
    )
    return list(collected.exchanges)


def only_error(exchanges: list[Exchange]) -> tuple[ErrorKind, str]:
    assert len(exchanges) == 1
    error = exchanges[0].error
    assert error is not None
    assert exchanges[0].response_text is None
    return error.kind, error.message


@respx.mock
async def test_read_timeout() -> None:
    respx.post(URL).mock(side_effect=httpx.ReadTimeout("read timed out"))
    kind, _ = only_error(await run_one(make_resolved()))
    assert kind is ErrorKind.TIMEOUT


@respx.mock
async def test_connect_error() -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("connection refused"))
    kind, _ = only_error(await run_one(make_resolved()))
    assert kind is ErrorKind.CONNECT


@respx.mock
async def test_tls_error_is_a_connect_failure_not_a_bypass() -> None:
    respx.post(URL).mock(side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"))
    kind, message = only_error(await run_one(make_resolved()))
    assert kind is ErrorKind.CONNECT
    assert "CERTIFICATE_VERIFY_FAILED" in message


@respx.mock
async def test_http_500_is_reported_after_a_single_attempt() -> None:
    # Architecture §Runner retries only 429/502/503/504; a plain 500 is not transient.
    route = respx.post(URL).mock(return_value=httpx.Response(500))
    exchanges = await run_one(make_resolved(), retries=3)
    kind, _ = only_error(exchanges)
    assert kind is ErrorKind.HTTP_STATUS
    assert exchanges[0].status_code is None
    assert route.call_count == 1


@respx.mock
async def test_http_503_is_retried_then_reported() -> None:
    route = respx.post(URL).mock(return_value=httpx.Response(503))
    exchanges = await run_one(make_resolved(), retries=2)
    kind, _ = only_error(exchanges)
    assert kind is ErrorKind.HTTP_STATUS
    assert route.call_count == 3
    assert exchanges[0].attempts == 3


@respx.mock
async def test_transient_503_then_success_recovers() -> None:
    responses = [httpx.Response(503), httpx.Response(200, json={"reply": "back"})]
    respx.post(URL).mock(side_effect=responses)
    exchanges = await run_one(make_resolved(), retries=2)
    assert exchanges[0].error is None
    assert exchanges[0].response_text == "back"
    assert exchanges[0].attempts == 2


@respx.mock
async def test_429_retry_after_is_honored_but_bounded() -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(429, headers={"retry-after": "999999"}),
    )
    recorder = SleepRecorder()
    await run_one(make_resolved(), retries=2, recorder=recorder)
    assert recorder.delays == [RETRY_AFTER_CAP_SECONDS, RETRY_AFTER_CAP_SECONDS]


@respx.mock
async def test_429_small_retry_after_is_used_as_is() -> None:
    respx.post(URL).mock(return_value=httpx.Response(429, headers={"retry-after": "2"}))
    recorder = SleepRecorder()
    await run_one(make_resolved(), retries=1, recorder=recorder)
    assert recorder.delays == [2.0]


@respx.mock
async def test_malformed_json() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, text="not json at all"))
    kind, _ = only_error(await run_one(make_resolved()))
    assert kind is ErrorKind.MALFORMED_RESPONSE


@respx.mock
async def test_empty_body() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, content=b""))
    kind, _ = only_error(await run_one(make_resolved()))
    assert kind is ErrorKind.MALFORMED_RESPONSE


@respx.mock
async def test_oversize_body() -> None:
    respx.post(URL).mock(return_value=httpx.Response(200, content=b"x" * 5000))
    kind, _ = only_error(await run_one(make_resolved(max_bytes=1000)))
    assert kind is ErrorKind.RESPONSE_TOO_LARGE


@respx.mock
async def test_redirect_loop_stops_at_max_hops() -> None:
    route = respx.post(URL).mock(
        return_value=httpx.Response(307, headers={"location": URL}),
    )
    kind, message = only_error(await run_one(make_resolved(network=FOLLOW)))
    assert kind is ErrorKind.POLICY
    assert "redirect" in message
    assert route.call_count == FOLLOW["max_redirects"] + 1


@respx.mock
async def test_redirect_to_private_ip_is_blocked() -> None:
    respx.post(URL).mock(
        return_value=httpx.Response(307, headers={"location": "http://10.0.0.5/internal"}),
    )
    internal = respx.route(host="10.0.0.5").mock(return_value=httpx.Response(200, json={}))
    kind, _ = only_error(await run_one(make_resolved(network=FOLLOW)))
    assert kind is ErrorKind.POLICY
    assert not internal.called


class RecordingLimiter(AsyncRateLimiter):
    """Real limiter that also records when each caller was released."""

    def __init__(self, rps: float) -> None:
        super().__init__(rps)
        self.released: list[float] = []

    async def acquire(self) -> None:
        await super().acquire()
        self.released.append(time.monotonic())


@respx.mock
async def test_rate_limit_spacing_end_to_end() -> None:
    arrivals: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        arrivals.append(time.monotonic())
        return httpx.Response(200, json={"reply": "ok"})

    respx.post(URL).mock(side_effect=handler)
    resolved = make_resolved()
    rps = 20.0
    limiter = RecordingLimiter(rps)
    settings = RunSettings(concurrency=5, requests_per_second=rps, retries=0, max_requests=500)
    collected = await collect_exchanges(
        HttpTarget(resolved, resolver=public_resolver),
        make_suite(5),
        settings,
        redactor=resolved.redactor,
        limiter=limiter,
    )
    assert all(e.error is None for e in collected.exchanges)
    interval = 1 / rps
    gaps = [later - earlier for earlier, later in itertools.pairwise(limiter.released)]
    assert len(gaps) == 4
    # Generous tolerance: Windows timers can wake early by several milliseconds.
    assert min(gaps) >= interval * 0.5
    assert arrivals[-1] - arrivals[0] >= interval * 4 * 0.5


@respx.mock
async def test_retries_never_exceed_the_configured_bound() -> None:
    route = respx.post(URL).mock(side_effect=httpx.ReadTimeout("slow"))
    exchanges = await run_one(make_resolved(), retries=4, count=3)
    assert route.call_count == 3 * (4 + 1)
    assert all(e.attempts == 5 for e in exchanges)


@respx.mock
async def test_error_messages_never_contain_the_secret_header_value() -> None:
    leaky = httpx.ConnectError(f"proxy said: Authorization Bearer {API_KEY} rejected")
    respx.post(URL).mock(side_effect=leaky)
    resolved = make_resolved()
    exchanges = await run_one(resolved)
    _, message = only_error(exchanges)
    assert API_KEY not in message
    assert "[REDACTED]" in message
    assert API_KEY not in exchanges[0].request_text
