"""Load payload suites safely: caps, restricted includes, template lint, regex checks."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path, PurePosixPath

from pydantic import ValidationError

from injectkit.errors import ConfigError, PayloadError
from injectkit.models import Payload, Suite
from injectkit.payloads.render import lint_template
from injectkit.yamlio import load_yaml

MAX_PAYLOADS = 200
MAX_SUITE_BYTES = 512 * 1024

_SUITE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_INCLUDE_SUFFIXES = frozenset({".yaml", ".yml"})


def _read_yaml(path: Path) -> object:
    try:
        return load_yaml(path, MAX_SUITE_BYTES)
    except ConfigError as exc:
        raise PayloadError(str(exc)) from None


def _include_path(base: Path, relative: object) -> Path:
    """Resolve an include entry, refusing anything that leaves ``base``."""
    if not isinstance(relative, str) or not relative:
        raise PayloadError("include must be a non-empty relative path string")
    pure = PurePosixPath(relative)
    unsafe = (
        "\\" in relative
        or ":" in relative
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.suffix.lower() not in _INCLUDE_SUFFIXES
    )
    if unsafe:
        raise PayloadError("include must be a relative .yaml path inside the suite directory")
    candidate = (base / pure).resolve()
    if not candidate.is_relative_to(base.resolve()):
        raise PayloadError("include must stay inside the suite directory")
    return candidate


def _expand(base: Path, entries: object) -> list[object]:
    if not isinstance(entries, list):
        raise PayloadError("'payloads' must be a list")
    expanded: list[object] = []
    for entry in entries:
        if isinstance(entry, dict) and set(entry) == {"include"}:
            included = _read_yaml(_include_path(base, entry["include"]))
            if not isinstance(included, list):
                raise PayloadError("an include file must contain a list of payloads")
            expanded.extend(included)
        else:
            expanded.append(entry)
        if len(expanded) > MAX_PAYLOADS:
            raise PayloadError(f"a suite may contain at most {MAX_PAYLOADS} payloads")
    return expanded


# A group whose body already contains a quantifier and which is itself quantified, such as
# ``(a+)+`` or ``(\w+\s?)*``: the classic exponential-backtracking shape. Heuristic only;
# overlapping alternations like ``(a|aa)+`` are not detected (documented residual risk).
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


def lint_regex(pattern: str) -> None:
    """Compile-check a response-check regex and refuse nested-quantifier shapes."""
    try:
        re.compile(pattern)
    except re.error:
        raise PayloadError("invalid regex check") from None
    if _NESTED_QUANTIFIER.search(pattern):
        raise PayloadError("regex check uses a nested quantifier (catastrophic backtracking risk)")


def _check_payload(payload: Payload) -> None:
    lint_template(payload.template)
    for check in payload.checks:
        if check.kind == "regex":
            try:
                lint_regex(check.pattern)
            except PayloadError as exc:
                raise PayloadError(f"payload '{payload.id}': {exc}") from None


def _build(document: object, base: Path) -> Suite:
    if not isinstance(document, dict):
        raise PayloadError("a suite must be a YAML mapping")
    data = {**document, "payloads": _expand(base, document.get("payloads"))}
    try:
        suite = Suite.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise PayloadError(f"invalid suite: {problems}") from None
    ids = [payload.id for payload in suite.payloads]
    if len(ids) != len(set(ids)):
        raise PayloadError("duplicate payload ids in suite")
    for payload in suite.payloads:
        _check_payload(payload)
    return suite


def _builtin_path(name: str) -> Path:
    if not _SUITE_NAME_RE.fullmatch(name):
        raise PayloadError("suite name must be lowercase letters, digits, '_' or '-'")
    resource = resources.files("injectkit.payloads") / "data" / f"{name}.yaml"
    path = Path(str(resource))
    if not path.is_file():
        raise PayloadError(f"unknown built-in suite '{name}'")
    return path


def load_suite(source: Path | str) -> Suite:
    """Load a suite from a file path, or a built-in suite by name (``str``)."""
    path = source if isinstance(source, Path) else _builtin_path(source)
    return _build(_read_yaml(path), path.parent)
