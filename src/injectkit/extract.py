"""Restricted response-path extraction: dot paths with list indices, nothing more."""

from __future__ import annotations

import re

from injectkit.errors import TargetError
from injectkit.models import ErrorKind

MAX_PATH_CHARS = 200

_PATH_RE = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")


def validate_path(path: str) -> str:
    """Return ``path`` if it is a plain dot path; raise ``ValueError`` otherwise."""
    if not path or len(path) > MAX_PATH_CHARS or not _PATH_RE.fullmatch(path):
        raise ValueError(
            f"response path must be 1-{MAX_PATH_CHARS} chars of dot-separated "
            "segments [A-Za-z0-9_-] (no wildcards, brackets or expressions)"
        )
    return path


def _step(node: object, segment: str, path: str) -> object:
    if isinstance(node, dict):
        if segment in node:
            return node[segment]
    elif isinstance(node, list) and segment.isascii() and segment.isdigit():
        index = int(segment)
        if index < len(node):
            return node[index]
    raise TargetError(ErrorKind.EXTRACTION, f"response path '{path}' not found at '{segment}'")


def extract(obj: object, path: str) -> str:
    """Walk ``path`` through parsed JSON ``obj``; the result must be a ``str``."""
    try:
        validate_path(path)
    except ValueError as exc:
        raise TargetError(ErrorKind.EXTRACTION, str(exc)) from None
    node = obj
    for segment in path.split("."):
        node = _step(node, segment, path)
    if not isinstance(node, str):
        raise TargetError(
            ErrorKind.EXTRACTION,
            f"response path '{path}' resolved to {type(node).__name__}, expected str",
        )
    return node
