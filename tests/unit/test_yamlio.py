from pathlib import Path

import pytest

from injectkit.errors import ConfigError
from injectkit.yamlio import MAX_YAML_BYTES, load_yaml


def write(tmp_path: Path, content: str | bytes) -> Path:
    path = tmp_path / "f.yaml"
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


def test_loads_plain_mapping(tmp_path: Path) -> None:
    assert load_yaml(write(tmp_path, "a: 1\nb: [x, y]\n")) == {"a": 1, "b": ["x", "y"]}


def test_rejects_python_object_tag(tmp_path: Path) -> None:
    payload = "x: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(ConfigError):
        load_yaml(write(tmp_path, payload))


def test_rejects_duplicate_keys(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="duplicate"):
        load_yaml(write(tmp_path, "a: 1\na: 2\n"))


def test_rejects_anchors_and_aliases(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"alias|anchor"):
        load_yaml(write(tmp_path, "a: &x [1, 2]\nb: *x\n"))


def test_rejects_oversize_file(tmp_path: Path) -> None:
    big = "a: " + "x" * (MAX_YAML_BYTES + 1)
    with pytest.raises(ConfigError, match="too large"):
        load_yaml(write(tmp_path, big))


def test_rejects_non_utf8(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="UTF-8"):
        load_yaml(write(tmp_path, b"a: \xff\xfe\n"))


def test_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_yaml(tmp_path / "nope.yaml")


def test_rejects_syntax_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_yaml(write(tmp_path, "a: [unclosed\n"))


def test_rejects_excessive_nesting(tmp_path: Path) -> None:
    deep = "a: " + "[" * 200 + "]" * 200 + "\n"
    with pytest.raises(ConfigError, match="nesting"):
        load_yaml(write(tmp_path, deep))
