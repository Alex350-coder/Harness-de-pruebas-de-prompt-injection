"""HTTP target: templated JSON POST with SSRF policy, size caps and manual redirects."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from injectkit.config import PLACEHOLDER, ResolvedTarget, is_sensitive_name
from injectkit.errors import NetworkPolicyError, TargetError
from injectkit.extract import extract
from injectkit.models import ErrorKind
from injectkit.netpolicy import Resolver, resolve_and_check, system_resolver
from injectkit.targets.base import TargetResponse

# Only these preserve method and body, so only these are followed (see Architecture §Targets).
_FOLLOWED_REDIRECTS = frozenset({307, 308})
_DEFAULT_PORTS = {"http": 80, "https": 443}

type Origin = tuple[str, str, int]


@dataclass(frozen=True, slots=True)
class _Raw:
    status: int
    location: str | None
    data: bytes
    retry_after: float | None = None


def substitute(node: Any, text: str) -> Any:
    """Return a copy of ``node`` with the placeholder leaf replaced by ``text``."""
    if isinstance(node, dict):
        return {key: substitute(child, text) for key, child in node.items()}
    if isinstance(node, list):
        return [substitute(child, text) for child in node]
    if node == PLACEHOLDER:
        return text
    return node


def _parse_retry_after(value: str | None) -> float | None:
    """Delta-seconds form only; HTTP-date values are ignored (backoff applies instead)."""
    if value is None or not (value.isascii() and value.isdigit()) or len(value) > 9:
        return None
    return float(value)


def _origin(url: str) -> Origin:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return (scheme, (parts.hostname or "").lower(), parts.port or _DEFAULT_PORTS[scheme])


class HttpTarget:
    def __init__(self, resolved: ResolvedTarget, *, resolver: Resolver = system_resolver) -> None:
        self._resolved = resolved
        self._resolver = resolver
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> Self:
        limits = self._resolved.config.limits
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(limits.timeout_seconds),
            follow_redirects=False,
            trust_env=False,
            limits=httpx.Limits(max_connections=limits.concurrency),
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    def _fail(
        self,
        kind: ErrorKind,
        message: str,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> TargetError:
        return TargetError(
            kind, self._resolved.redactor.mask(message), status_code=status, retry_after=retry_after
        )

    def _transport_failure(self, exc: Exception) -> TargetError:
        if isinstance(exc, httpx.TimeoutException):
            kind = ErrorKind.TIMEOUT
        elif isinstance(exc, httpx.TransportError):
            kind = ErrorKind.CONNECT
        else:
            kind = ErrorKind.INTERNAL
        return self._fail(kind, self._resolved.redactor.mask_exception(exc))

    def _request_headers(self) -> dict[str, str]:
        headers = dict(self._resolved.headers)
        if not any(name.lower() == "content-type" for name in headers):
            headers["Content-Type"] = "application/json"
        if not any(name.lower() == "accept-encoding" for name in headers):
            headers["Accept-Encoding"] = (
                "identity"  # no decompression: the size cap counts real bytes
            )
        return headers

    async def send(self, text: str) -> TargetResponse:
        client = self._client
        if client is None:
            raise self._fail(ErrorKind.INTERNAL, "target used outside 'async with'")
        body = json.dumps(substitute(self._resolved.config.request.body, text)).encode("ascii")
        deadline = self._resolved.config.limits.timeout_seconds
        try:
            async with asyncio.timeout(deadline):
                raw = await self._follow(client, body)
        except TimeoutError:
            raise self._fail(
                ErrorKind.TIMEOUT, f"no complete response within {deadline}s"
            ) from None
        return TargetResponse(text=self._parse(raw.data), status_code=raw.status)

    async def _follow(self, client: httpx.AsyncClient, body: bytes) -> _Raw:
        network = self._resolved.config.network
        url = self._resolved.config.request.url
        headers = self._request_headers()
        last_hop = network.max_redirects if network.follow_redirects else 0
        for hop in range(last_hop + 1):
            await self._enforce_policy(url)
            raw = await self._fetch(client, url, headers, body)
            if 200 <= raw.status < 300:
                return raw
            if not (network.follow_redirects and raw.status in _FOLLOWED_REDIRECTS):
                raise self._fail(
                    ErrorKind.HTTP_STATUS, f"HTTP {raw.status}", raw.status, raw.retry_after
                )
            if hop == last_hop:
                raise self._fail(ErrorKind.POLICY, "too many redirects")
            try:
                url, headers = self._next_hop(url, raw, headers)
            except ValueError:
                raise self._fail(ErrorKind.POLICY, "redirect target is not a valid URL") from None
        raise self._fail(ErrorKind.INTERNAL, "redirect loop ended unexpectedly")

    def _next_hop(self, url: str, raw: _Raw, headers: dict[str, str]) -> tuple[str, dict[str, str]]:
        if not raw.location:
            raise self._fail(
                ErrorKind.HTTP_STATUS, f"HTTP {raw.status} without Location", raw.status
            )
        target = urldefrag(urljoin(url, raw.location)).url
        if not all(33 <= ord(c) < 127 for c in target):
            raise self._fail(ErrorKind.POLICY, "redirect target is not a plain ASCII URL")
        parts = urlsplit(target)
        if parts.scheme not in _DEFAULT_PORTS or not parts.hostname or parts.username is not None:
            raise self._fail(ErrorKind.POLICY, "redirect target is not an allowed URL")
        if urlsplit(url).scheme == "https" and parts.scheme != "https":
            raise self._fail(ErrorKind.POLICY, "redirect would downgrade https to http")
        if _origin(target) != _origin(url):
            headers = {k: v for k, v in headers.items() if not is_sensitive_name(k)}
        return target, headers

    async def _enforce_policy(self, url: str) -> None:
        try:
            parts = urlsplit(url)
            port = parts.port or _DEFAULT_PORTS.get(parts.scheme, 0)
            await resolve_and_check(
                parts.hostname or "",
                port,
                self._resolved.config.network.policy,
                resolver=self._resolver,
            )
        except (NetworkPolicyError, ValueError) as exc:
            raise self._fail(ErrorKind.POLICY, str(exc)) from None

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, headers: dict[str, str], body: bytes
    ) -> _Raw:
        method = self._resolved.config.request.method
        try:
            async with client.stream(method, url, content=body, headers=headers) as response:
                location = response.headers.get("location")
                if not 200 <= response.status_code < 300:
                    retry = _parse_retry_after(response.headers.get("retry-after"))
                    return _Raw(response.status_code, location, b"", retry)
                return _Raw(response.status_code, location, await self._read_capped(response))
        except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError) as exc:
            raise self._transport_failure(exc) from None

    async def _read_capped(self, response: httpx.Response) -> bytes:
        limit = self._resolved.config.response.max_bytes
        declared = response.headers.get("content-length", "")
        if declared.isascii() and declared.isdigit() and int(declared) > limit:
            raise self._fail(ErrorKind.RESPONSE_TOO_LARGE, f"response exceeds {limit} bytes")
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in ("", "identity"):
            raise self._fail(ErrorKind.MALFORMED_RESPONSE, "compressed responses are not accepted")
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_raw():
            total += len(chunk)
            if total > limit:
                raise self._fail(ErrorKind.RESPONSE_TOO_LARGE, f"response exceeds {limit} bytes")
            chunks.append(chunk)
        return b"".join(chunks)

    def _parse(self, data: bytes) -> str:
        try:
            parsed = json.loads(data)
        except (ValueError, RecursionError):
            raise self._fail(ErrorKind.MALFORMED_RESPONSE, "response is not valid JSON") from None
        return extract(parsed, self._resolved.config.response.path)
