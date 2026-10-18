"""check-target: one benign request to verify connectivity, policy and extraction."""

from __future__ import annotations

import time
from dataclasses import dataclass

from injectkit.config import ResolvedTarget
from injectkit.redact import strip_control
from injectkit.targets.http import HttpTarget

BENIGN_MESSAGE = "Hello! Please reply with a short greeting."
MAX_SHOWN_CHARS = 300


@dataclass(frozen=True, slots=True)
class ProbeResult:
    status_code: int
    latency_ms: float
    text: str


async def probe(resolved: ResolvedTarget) -> ProbeResult:
    """Send the fixed benign message once. Raises ``TargetError`` on any failure."""
    async with HttpTarget(resolved) as target:
        began = time.perf_counter()
        reply = await target.send(BENIGN_MESSAGE)
        latency_ms = (time.perf_counter() - began) * 1000
    return ProbeResult(reply.status_code, latency_ms, reply.text)


def safe_excerpt(resolved: ResolvedTarget, text: str) -> str:
    """Redacted, control-stripped, truncated text for terminal display."""
    cleaned = strip_control(resolved.redactor.mask(text))
    if len(cleaned) <= MAX_SHOWN_CHARS:
        return cleaned
    return f"{cleaned[:MAX_SHOWN_CHARS]}… (truncated)"
