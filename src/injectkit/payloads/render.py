"""Sandboxed payload rendering. Templates may only output ``canary_a`` / ``canary_b``."""

from __future__ import annotations

import re

from jinja2 import StrictUndefined, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment

from injectkit.errors import PayloadError
from injectkit.models import Canary, Payload
from injectkit.payloads.canary import assert_not_in_request

MAX_TEMPLATE_BYTES = 8 * 1024

_ALLOWED_OUTPUT = re.compile(r"\{\{\s*(?:canary_a|canary_b)\s*\}\}")
_FORBIDDEN_TOKENS = ("{%", "{#", "__", "{{{", "}}}")
_ADJACENT_OUTPUTS = re.compile(r"}}{{")

# No loader, no extensions; the immutable sandbox plus StrictUndefined is the second layer
# behind the lint. Output is plain text for an API (no HTML), so no autoescaping is wanted.
_ENVIRONMENT = ImmutableSandboxedEnvironment(undefined=StrictUndefined, keep_trailing_newline=True)


def lint_template(template: str) -> None:
    """Reject anything except literal text and ``{{ canary_a }}`` / ``{{ canary_b }}``."""
    if len(template.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise PayloadError(f"template is too large (limit {MAX_TEMPLATE_BYTES} bytes)")
    if any(token in template for token in _FORBIDDEN_TOKENS):
        raise PayloadError("template uses forbidden syntax (blocks, comments, '__' or '{{{')")
    if _ADJACENT_OUTPUTS.search(template):
        raise PayloadError("adjacent {{ }} outputs could rebuild the canary; separate them")
    leftover = _ALLOWED_OUTPUT.sub("", template)
    if "{{" in leftover or "}}" in leftover:
        raise PayloadError("template may only output the variables canary_a and canary_b")


def render(payload: Payload, canary: Canary) -> str:
    """Render ``payload.template`` with the two canary halves (never the whole value)."""
    lint_template(payload.template)
    try:
        text = _ENVIRONMENT.from_string(payload.template).render(
            canary_a=canary.half_a, canary_b=canary.half_b
        )
    except TemplateError as exc:
        raise PayloadError(
            f"payload '{payload.id}' failed to render: {type(exc).__name__}"
        ) from None
    assert_not_in_request(canary, text)
    return text
