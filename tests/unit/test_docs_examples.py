"""Documentation checks: config examples validate with the real loader, relative links resolve."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from injectkit.config import ResolvedTarget, load_config
from injectkit.errors import ConfigError

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "README.md"
DOC_FILES = [README, *sorted((ROOT / "docs").glob("*.md"))]
# At least 6 characters (the minimum for env-sourced secrets). Never a real credential.
DUMMY_ENV_VALUE = "dummy-value-0123456789"

_CONFIG_BLOCK = re.compile(r"^```yaml config[ \t]*\n(.*?)^```[ \t]*$", re.MULTILINE | re.DOTALL)
_FENCED = re.compile(r"^```.*?^```[ \t]*$", re.MULTILINE | re.DOTALL)
_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_VALUE_ENV = re.compile(r"^\s*value_env:\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
_HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t]*$", re.MULTILINE)
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def read_doc(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def config_blocks(path: Path) -> list[str]:
    """Bodies of the fenced blocks tagged exactly ``yaml config``."""
    return _CONFIG_BLOCK.findall(read_doc(path))


def _env_for(block: str) -> dict[str, str]:
    """Dummy values for every environment variable the block refers to."""
    names = set(_ENV_REF.findall(block)) | set(_VALUE_ENV.findall(block))
    return dict.fromkeys(sorted(names), DUMMY_ENV_VALUE)


def validate_config_block(block: str, workdir: Path) -> ResolvedTarget:
    """Write the block to a file and load it with the project's own loader."""
    path = workdir / "target.yaml"
    path.write_text(block, encoding="utf-8")
    return load_config(path, env=_env_for(block))


def _without_fences(text: str) -> str:
    return _FENCED.sub("", text)


def _slug(heading: str) -> str:
    """GitHub-style anchor: no backticks, lower case, punctuation removed, spaces to hyphens."""
    plain = heading.replace("`", "").strip().lower()
    return re.sub(r"[^\w\- ]", "", plain).replace(" ", "-")


def _anchors(text: str) -> set[str]:
    return {_slug(heading) for heading in _HEADING.findall(_without_fences(text))}


def broken_links(path: Path) -> list[str]:
    """Relative links whose file, or heading anchor inside a Markdown file, does not exist."""
    problems: list[str] = []
    for raw in _LINK.findall(_without_fences(read_doc(path))):
        if _SCHEME.match(raw):
            continue  # http, https, mailto and similar: not checked here
        target, _, anchor = raw.partition("#")
        linked = (path.parent / target).resolve() if target else path
        if not linked.is_file():
            problems.append(f"{raw}: no such file")
        elif anchor and linked.suffix == ".md" and anchor not in _anchors(read_doc(linked)):
            problems.append(f"{raw}: no such heading")
    return problems


CONFIG_BLOCKS = [
    (path.relative_to(ROOT).as_posix(), block)
    for path in DOC_FILES
    for block in config_blocks(path)
]

MINIMAL_BLOCK = """\
version: 1
authorization:
  confirmed: true
  scope_note: "Own staging chatbot"
name: control-target
request:
  url: https://staging.example.com/api/chat
  body:
    message: "{{payload}}"
response:
  path: reply
"""


def test_docs_scan_covers_readme_and_docs_directory() -> None:
    names = {path.name for path in DOC_FILES}
    expected = {"README.md", "config.md", "authorization.md", "reporting.md", "detectors.md"}
    assert expected <= names
    assert "payloads.md" in names and "demo.md" in names


def test_docs_contain_config_blocks_including_config_reference() -> None:
    assert CONFIG_BLOCKS, "no ```yaml config block in README.md or docs/*.md"
    assert any(source == "docs/config.md" for source, _ in CONFIG_BLOCKS)


@pytest.mark.parametrize(
    ("source", "block"),
    CONFIG_BLOCKS,
    ids=[f"{source}#{index}" for index, (source, _) in enumerate(CONFIG_BLOCKS)],
)
def test_config_block_validates_with_real_loader(source: str, block: str, tmp_path: Path) -> None:
    resolved = validate_config_block(block, tmp_path)
    assert resolved.config.version == 1, source


def test_positive_control_minimal_block_is_accepted(tmp_path: Path) -> None:
    resolved = validate_config_block(MINIMAL_BLOCK, tmp_path)
    assert resolved.config.name == "control-target"


@pytest.mark.parametrize(
    ("block", "message"),
    [
        pytest.param(
            MINIMAL_BLOCK.replace("confirmed: true", "confirmed: false"),
            "authorization.confirmed",
            id="authorization-not-confirmed",
        ),
        pytest.param(
            MINIMAL_BLOCK + "limits:\n  concurency: 4\n",
            "concurency",
            id="unknown-key-is-rejected",
        ),
        pytest.param(
            MINIMAL_BLOCK.replace('message: "{{payload}}"', 'message: "hello"'),
            "body",
            id="body-without-placeholder",
        ),
    ],
)
def test_invalid_config_block_is_rejected_by_the_same_helper(
    block: str, message: str, tmp_path: Path
) -> None:
    with pytest.raises(ConfigError, match=message):
        validate_config_block(block, tmp_path)


@pytest.mark.parametrize("doc", DOC_FILES, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_relative_links_resolve(doc: Path) -> None:
    assert broken_links(doc) == []


def test_broken_link_and_anchor_are_reported_but_code_fences_are_ignored(tmp_path: Path) -> None:
    doc = tmp_path / "doc.md"
    doc.write_text(
        "# Title\n\n"
        "[missing](nope.md) [bad anchor](#no-such-heading) [good anchor](#title)\n\n"
        "```text\n[inside a fence](ignored.md)\n```\n",
        encoding="utf-8",
    )
    problems = broken_links(doc)
    assert problems == ["nope.md: no such file", "#no-such-heading: no such heading"]
