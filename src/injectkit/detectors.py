"""Deterministic detectors, text normalization and verdict aggregation."""

from __future__ import annotations

import unicodedata
from typing import Protocol

from injectkit.models import Exchange, Finding, Payload

_MAX_NORMALIZE_PASSES = 4


class Detector(Protocol):
    """Inspects one ``Exchange`` and returns zero or more findings.

    ``limitation`` is a fixed sentence stating what the evidence does *not* prove; it is
    copied onto every finding so reports never overstate a result.
    """

    name: str
    limitation: str

    def check(self, exchange: Exchange, payload: Payload) -> list[Finding]: ...


def _normalize_once(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(c for c in text if unicodedata.category(c) != "Cf")
    text = text.casefold()
    return " ".join(text.split())


def normalize(text: str) -> str:
    """NFKC, strip format (Cf) characters, casefold, collapse whitespace.

    Casefolding can produce characters that NFKC would change again, so the steps repeat
    until the text stops changing (bounded), which makes the function idempotent.
    """
    for _ in range(_MAX_NORMALIZE_PASSES):
        normalized = _normalize_once(text)
        if normalized == text:
            return normalized
        text = normalized
    return text


def squash(text: str) -> str:
    """``normalize`` and then drop all whitespace, to catch indicators split by spaces."""
    return normalize(text).replace(" ", "")
