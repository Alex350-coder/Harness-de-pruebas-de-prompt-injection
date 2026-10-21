"""SARIF 2.1.0 output for GitHub Code Scanning. Everything passes through the ``Redactor``.

Findings are runtime observations, not source defects, so every result points at the target
config file (line 1). The fingerprint hashes target id + payload id + detector only, so it is
stable across runs and never contains evidence or secrets.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote

from injectkit.models import Finding, Outcome, RunResult, Severity
from injectkit.redact import Redactor

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
RULE_PREFIX = "injectkit/"
_FALLBACK_URI = "target.yaml"
ERROR_RATE_LIMIT = 0.5  # same threshold as the CLI exit code 3

# GitHub maps security-severity (a string in 0.1-10.0) to low/medium/high/critical.
_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.INFO: "1.0",
    Severity.LOW: "3.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}
_SEVERITY_ORDER = tuple(Severity)
_LEVELS = {Outcome.CONFIRMED: "error", Outcome.POTENTIAL: "warning"}
_RULE_HELP_LIMIT = 1024


def config_uri(path: Path, *, base: Path | None = None) -> str:
    """A relative, percent-encoded POSIX path for the config file (never absolute, no ``..``).

    GitHub resolves it from the repository root, so run InjectKit from there. A path outside
    ``base`` (default: the current directory) is reported by file name only, so an absolute
    local path is never written into a report.
    """
    root = (base or Path.cwd()).resolve()
    try:
        relative = path.resolve().relative_to(root).as_posix()
    except ValueError:
        relative = PurePosixPath(path.name.replace("\\", "/")).name
    parts = [part for part in relative.split("/") if part not in {"", ".", ".."}]
    return quote("/".join(parts), safe="/") or _FALLBACK_URI


def _fingerprint(finding: Finding, occurrence: int) -> str:
    key = "\x1f".join((finding.target_id, finding.payload_id, finding.detector))
    return f"{hashlib.sha256(key.encode('utf-8')).hexdigest()[:32]}:{occurrence}"


def _first_sentence(text: str) -> str:
    return text.strip().splitlines()[0].strip() if text.strip() else "-"


def _message(finding: Finding) -> str:
    # GitHub shows only the first sentence when space is short, so it carries the verdict.
    head = (
        f"{finding.outcome.value.upper()} {finding.detector} indicator "
        f"({finding.matched_indicator}) for payload {finding.payload_id}."
    )
    evidence = _first_sentence(finding.evidence)
    return f"{head} Evidence: {evidence} Limitation: {finding.limitations}"


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    by_category: dict[str, list[Finding]] = {}
    for finding in findings:
        by_category.setdefault(finding.category, []).append(finding)
    rules: list[dict[str, Any]] = []
    for category in sorted(by_category):
        group = by_category[category]
        top = max((f.severity for f in group), key=_SEVERITY_ORDER.index)
        remediation = " ".join(sorted({f.remediation for f in group if f.remediation}))
        title = f"Prompt-injection test category: {category}"
        rules.append(
            {
                "id": f"{RULE_PREFIX}{category}",
                "name": category,
                "shortDescription": {"text": title},
                "fullDescription": {
                    "text": f"{title}. A payload in this category produced an indicator in the "
                    "target's reply. A finding is evidence of instruction-following, not proof "
                    "of impact."
                },
                "help": {
                    "text": (remediation or "Review the finding manually.")[:_RULE_HELP_LIMIT]
                },
                "defaultConfiguration": {"level": "warning"},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[top],
                    "tags": ["security", "prompt-injection"],
                },
            }
        )
    return rules


def _results(findings: list[Finding], uri: str) -> list[dict[str, Any]]:
    seen: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        base = _fingerprint(finding, 1).split(":", 1)[0]
        seen[base] = seen.get(base, 0) + 1
        results.append(
            {
                "ruleId": f"{RULE_PREFIX}{finding.category}",
                "level": _LEVELS[finding.outcome],
                "message": {"text": _message(finding)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {
                                "startLine": 1,
                                "startColumn": 1,
                                "endLine": 1,
                                "endColumn": 1,
                            },
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": _fingerprint(finding, seen[base])
                },
                "properties": {
                    "payload_id": finding.payload_id,
                    "detector": finding.detector,
                    "outcome": finding.outcome.value,
                    "confidence": finding.confidence.value,
                    "severity": finding.severity.value,
                    "target_id": finding.target_id,
                    "remediation": finding.remediation,
                },
            }
        )
    return results


def _invocation(run: RunResult) -> dict[str, Any]:
    errors = [r for r in run.results if r.error is not None]
    too_many_errors = bool(run.results) and len(errors) / len(run.results) > ERROR_RATE_LIMIT
    invocation: dict[str, Any] = {
        # Mirrors the CLI: interrupted (130) or more than half errored (3) is not a success,
        # so a consumer can avoid treating an empty result list as "all alerts fixed".
        "executionSuccessful": not (run.interrupted or too_many_errors),
        "startTimeUtc": run.started_at.isoformat().replace("+00:00", "Z"),
        "endTimeUtc": run.finished_at.isoformat().replace("+00:00", "Z"),
    }
    if errors:
        invocation["toolExecutionNotifications"] = [
            {
                "level": "error",
                "message": {
                    "text": f"payload {r.payload_id}: {r.error.kind.value}: {r.error.message}"
                    if r.error is not None
                    else f"payload {r.payload_id}: error"
                },
            }
            for r in errors
        ]
    return invocation


def build_sarif(run: RunResult, *, config_uri: str) -> dict[str, Any]:
    findings = [f for result in run.results for f in result.findings]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "injectkit",
                        "version": run.tool_version,
                        "rules": _rules(findings),
                    }
                },
                "invocations": [_invocation(run)],
                "results": _results(findings, config_uri),
                "properties": {
                    "run_id": run.run_id,
                    "suite": run.suite,
                    "target_id": run.target_id,
                },
            }
        ],
    }


def to_sarif(run: RunResult, redactor: Redactor, *, config_uri: str) -> str:
    """Serialize ``run`` to deterministic SARIF 2.1.0 with every string redacted."""
    document: Any = redactor.mask_json(build_sarif(run, config_uri=config_uri))
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
    return redactor.mask(text) + "\n"
