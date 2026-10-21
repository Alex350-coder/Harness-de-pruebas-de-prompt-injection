"""Static checks of the GitHub workflows (SEC-12, SEC-14): least privilege, pinned actions."""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}(\s|$)")
MANDATORY_CI_JOBS = {"quality", "windows-smoke", "audit", "secrets", "build-smoke"}
WRITE_PERMISSIONS = {"security-events", "id-token", "contents", "pull-requests", "packages"}


def load(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def triggers(document: dict[str, Any]) -> dict[str, Any]:
    # YAML 1.1 parses the bare key `on` as the boolean True.
    value = document.get("on", document.get(True))
    return value if isinstance(value, dict) else {name: None for name in value or []}


def uses_lines(path: Path) -> list[str]:
    found = []
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*(?:-\s+)?uses:\s*(\S.*)$", line)
        if match:
            found.append(match.group(1))
    return found


def test_workflows_exist() -> None:
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "audit.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_third_party_action_is_pinned_to_a_commit_sha(path: Path) -> None:
    for reference in uses_lines(path):
        assert PINNED.match(reference), f"{path.name}: '{reference}' is not pinned to a SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_target_and_no_shared_secrets_on_prs(path: Path) -> None:
    document = load(path)
    assert "pull_request_target" not in triggers(document)
    text = path.read_text(encoding="utf-8")
    assert "pull_request_target" not in text.replace("`pull_request_target`", "")
    assert not re.search(r"\$\{\{\s*secrets\.", text), "workflows must not read repository secrets"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_default_token_is_read_only(path: Path) -> None:
    document = load(path)
    if path.name == "release.yml":
        # The release job is the only one that may widen permissions, per job.
        assert document.get("permissions") in ({}, {"contents": "read"})
        return
    assert document.get("permissions") == {"contents": "read"}


def test_ci_has_every_mandatory_job_and_no_job_widens_permissions() -> None:
    jobs = load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]
    assert set(jobs) >= MANDATORY_CI_JOBS
    for name, job in jobs.items():
        permissions = job.get("permissions", {})
        assert not set(permissions) & WRITE_PERMISSIONS, name


def test_secret_scan_uses_full_history_and_a_checksum_verified_binary() -> None:
    job = load(ROOT / ".github" / "workflows" / "ci.yml")["jobs"]["secrets"]
    checkout = job["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0
    assert re.fullmatch(r"[0-9a-f]{64}", job["env"]["GITLEAKS_SHA256"])
    assert "sha256sum -c" in str(job["steps"])


def test_audit_runs_weekly_and_uses_locked_hashed_requirements() -> None:
    document = load(ROOT / ".github" / "workflows" / "audit.yml")
    assert "schedule" in triggers(document)
    text = (ROOT / ".github" / "workflows" / "audit.yml").read_text(encoding="utf-8")
    assert "--locked" in text
    assert "--require-hashes" in text


def test_dependabot_covers_only_actions_and_uv() -> None:
    document = load(ROOT / ".github" / "dependabot.yml")
    assert {u["package-ecosystem"] for u in document["updates"]} == {"github-actions", "uv"}


def test_checker_rejects_an_unpinned_reference() -> None:
    assert not PINNED.match("actions/checkout@v4")
    assert not PINNED.match("actions/checkout@main")
