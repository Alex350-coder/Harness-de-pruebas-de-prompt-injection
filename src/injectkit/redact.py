"""Central secret masking: every string leaving the process passes through here."""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import quote, quote_plus

_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# C0/C1 controls plus bidi overrides, zero-width and BOM characters (terminal spoofing).
# Also invisible "smuggling" characters: line/paragraph separators, word joiners and invisible
# operators, Arabic letter mark, Mongolian vowel separator, interlinear annotation, and the
# Unicode tag block.
_CONTROL = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069"
    r"\ufeff\ufff9-\ufffb\U000e0000-\U000e007f]"
)


def strip_control(text: str) -> str:
    """Remove ANSI escape sequences and control characters (keeps ``\\n`` and ``\\t``)."""
    text = _ANSI_OSC.sub("", text)
    text = _ANSI_CSI.sub("", text)
    return _CONTROL.sub("", text)


def _lower_percent(encoded: str) -> str:
    return re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), encoded)


class Redactor:
    """Registers secret values and masks them (and common encodings) in any output."""

    def __init__(self) -> None:
        # variant text -> replacement marker
        self._variants: dict[str, str] = {}

    def add(self, value: str, label: str | None = None) -> None:
        """Register a secret. Empty values are ignored (config enforces minimum lengths)."""
        if not value:
            return
        marker = f"[REDACTED:{label}]" if label else "[REDACTED]"
        forms = {
            value,
            quote(value, safe=""),
            quote_plus(value),
            json.dumps(value)[1:-1],
            base64.b64encode(value.encode()).decode(),
            _lower_percent(quote(value, safe="")),
        }
        for form in forms:
            if form:
                self._variants.setdefault(form, marker)

    def mask(self, text: str) -> str:
        """Replace every registered secret variant, longest first."""
        for variant in sorted(self._variants, key=len, reverse=True):
            text = text.replace(variant, self._variants[variant])
        return text

    def mask_exception(self, exc: BaseException) -> str:
        return f"{type(exc).__name__}: {self.mask(str(exc))}"

    def mask_json(self, obj: Any) -> Any:
        """Return a copy of a JSON-like structure with all strings masked."""
        if isinstance(obj, str):
            return self.mask(obj)
        if isinstance(obj, dict):
            return {self.mask(str(k)): self.mask_json(v) for k, v in obj.items()}
        if isinstance(obj, list | tuple):
            return [self.mask_json(v) for v in obj]
        return obj
