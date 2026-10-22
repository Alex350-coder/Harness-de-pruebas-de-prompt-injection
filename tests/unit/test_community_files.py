"""SECURITY.md, CONTRIBUTING.md and LICENSE exist and invent no identities (P5-T05)."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ("SECURITY.md", "CONTRIBUTING.md", "LICENSE")
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
# Hosts that may appear in the files; any other URL would be an invented contact.
ALLOWED_URL_HOSTS = {"docs.astral.sh", "www.apache.org"}


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", FILES)
def test_file_exists_and_is_not_empty(name: str) -> None:
    assert len(read(name).strip()) > 200


@pytest.mark.parametrize("name", FILES)
def test_no_email_addresses_and_only_known_url_hosts(name: str) -> None:
    text = read(name)
    assert not EMAIL.search(text)
    for host in re.findall(r"https?://([^/\s)>\]]+)", text):
        assert host in ALLOWED_URL_HOSTS, f"{name}: unexpected URL host {host}"


def test_security_contact_is_an_explicit_placeholder() -> None:
    text = read("SECURITY.md")
    assert "TODO-USER: security reporting contact" in text
    assert text.count("TODO-USER") == 1


@pytest.mark.parametrize("name", ["SECURITY.md", "CONTRIBUTING.md"])
def test_relative_links_resolve(name: str) -> None:
    for target in LINK.findall(read(name)):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        assert (ROOT / target).exists(), f"{name}: broken link {target}"


def test_license_is_apache_2_without_an_invented_copyright_holder() -> None:
    text = read("LICENSE")
    assert "Apache License" in text
    assert "Version 2.0, January 2004" in text
    assert not re.search(r"Copyright \(c\) \d{4}", text)


def test_contributing_gate_commands_match_ci() -> None:
    contributing = read("CONTRIBUTING.md")
    ci = read(".github/workflows/ci.yml")
    for command in (
        "uv run ruff format --check .",
        "uv run ruff check .",
        "uv run mypy",
        "uv run pytest --cov",
    ):
        assert command in contributing
        assert command in ci


def test_issue_templates_are_intentionally_omitted() -> None:
    assert not (ROOT / ".github" / "ISSUE_TEMPLATE").exists()
