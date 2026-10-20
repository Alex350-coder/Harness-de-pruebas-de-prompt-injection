"""Schema-versioned JSON report. Everything passes through the ``Redactor`` before output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from injectkit.models import RunResult, TestResult
from injectkit.redact import Redactor
from injectkit.report import sanitize_url

SCHEMA_VERSION = "1"


class _Doc(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ToolInfo(_Doc):
    name: Literal["injectkit"]
    version: str


class TargetInfo(_Doc):
    id: str
    url: str | None


class RunInfo(_Doc):
    run_id: str
    suite: str
    started_at: datetime
    finished_at: datetime
    interrupted: bool
    settings: dict[str, str | int | float | bool]


class JsonReport(_Doc):
    """The JSON document layout (also the source of ``docs/report-schema.json``)."""

    schema_version: Literal["1"]
    tool: ToolInfo
    target: TargetInfo
    run: RunInfo
    summary: dict[str, int]
    results: tuple[TestResult, ...]
    disclaimer: str


DISCLAIMER = (
    "NO_INDICATOR and INCONCLUSIVE are not evidence that the target is secure; "
    "findings are limited to what each detector can observe."
)


def build_report(
    run: RunResult, *, target_url: str | None = None, include_responses: bool = False
) -> JsonReport:
    results = run.results
    if not include_responses:
        results = tuple(
            r.model_copy(update={"response_excerpt": None, "response_truncated": False})
            for r in results
        )
    return JsonReport(
        schema_version=SCHEMA_VERSION,
        tool=ToolInfo(name="injectkit", version=run.tool_version),
        target=TargetInfo(
            id=run.target_id, url=None if target_url is None else sanitize_url(target_url)
        ),
        run=RunInfo(
            run_id=run.run_id,
            suite=run.suite,
            started_at=run.started_at,
            finished_at=run.finished_at,
            interrupted=run.interrupted,
            settings=dict(run.settings_summary),
        ),
        summary=dict(run.counts),
        results=results,
        disclaimer=DISCLAIMER,
    )


def to_json(
    run: RunResult,
    redactor: Redactor,
    *,
    target_url: str | None = None,
    include_responses: bool = False,
) -> str:
    """Serialize ``run`` to deterministic (sorted-key) JSON with every string redacted.

    Request headers are never part of the model; the target URL loses userinfo and query.
    """
    report = build_report(run, target_url=target_url, include_responses=include_responses)
    document: Any = redactor.mask_json(report.model_dump(mode="json"))
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
    return redactor.mask(text) + "\n"


def report_schema() -> dict[str, Any]:
    """JSON Schema of the report document."""
    return JsonReport.model_json_schema()


def schema_text() -> str:
    return json.dumps(report_schema(), indent=2, sort_keys=True) + "\n"
