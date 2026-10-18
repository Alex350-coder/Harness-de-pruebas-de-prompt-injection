"""Safe YAML loading: size-limited, UTF-8 only, no aliases, no duplicate keys."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import yaml
from yaml.constructor import ConstructorError
from yaml.events import Event
from yaml.nodes import MappingNode, Node

from injectkit.errors import ConfigError

MAX_YAML_BYTES = 256 * 1024
MAX_YAML_DEPTH = 32


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects anchors/aliases and duplicate mapping keys."""

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        peek = cast(Callable[[], Event], self.peek_event)
        event = peek()
        mark = cast("yaml.error.Mark | None", event.start_mark)
        if isinstance(event, yaml.AliasEvent):
            raise yaml.composer.ComposerError(None, None, "YAML aliases are not allowed", mark)
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(None, None, "YAML anchors are not allowed", mark)
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                is_duplicate = key in seen
            except TypeError as exc:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable key",
                    key_node.start_mark,
                ) from exc
            if is_duplicate:
                raise ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found duplicate key",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _depth(value: Any) -> int:
    """Iterative nesting depth of a loaded document."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if deepest > MAX_YAML_DEPTH:
            return deepest
        if isinstance(item, dict):
            stack.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, level + 1) for child in item)
    return deepest


def load_yaml(path: Path, max_bytes: int = MAX_YAML_BYTES) -> object:
    """Load a YAML file safely. Raises ``ConfigError`` for every failure."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read file '{path.name}': {exc.strerror}") from exc
    if len(raw) > max_bytes:
        raise ConfigError(f"file '{path.name}' is too large (limit {max_bytes} bytes)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"file '{path.name}' is not valid UTF-8") from exc
    loader = _StrictLoader(text)
    try:
        document = loader.get_single_data()
    except yaml.YAMLError as exc:
        raise ConfigError(_describe(exc)) from None
    except RecursionError:
        raise ConfigError("YAML nesting is too deep") from None
    finally:
        loader.dispose()
    if _depth(document) > MAX_YAML_DEPTH:
        raise ConfigError(f"YAML nesting is too deep (limit {MAX_YAML_DEPTH})")
    return document


def _describe(exc: yaml.YAMLError) -> str:
    problem = getattr(exc, "problem", None) or "invalid YAML"
    mark = getattr(exc, "problem_mark", None)
    where = f" (line {mark.line + 1})" if mark is not None else ""
    return f"invalid YAML: {problem}{where}"
