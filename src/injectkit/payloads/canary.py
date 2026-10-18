"""Per-test canaries. The full value is never sent; only its two halves are."""

from __future__ import annotations

import re
import secrets

from injectkit.errors import PayloadError
from injectkit.models import Canary

CANARY_PREFIX = "INJK-"
CANARY_HEX_BYTES = 8  # 16 hex characters
CANARY_RE = re.compile(re.escape(CANARY_PREFIX) + r"[0-9a-f]{16}")
# Split inside the hex part, so each half is too short to match CANARY_RE on its own.
_SPLIT_AT = len(CANARY_PREFIX) + 8


def new_canary() -> Canary:
    value = CANARY_PREFIX + secrets.token_hex(CANARY_HEX_BYTES)
    return Canary(value=value, half_a=value[:_SPLIT_AT], half_b=value[_SPLIT_AT:])


def assert_not_in_request(canary: Canary, request_text: str) -> None:
    """Raise if the full canary value is present: echo must never count as success."""
    if canary.value in request_text:
        raise PayloadError("rendered request contains the full canary value")
