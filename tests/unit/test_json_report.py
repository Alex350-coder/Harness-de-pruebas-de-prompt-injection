import json
import os
from collections.abc import Callable
from pathlib import Path

import jsonschema
import pytest

from injectkit.errors import ReportError
from injectkit.models import Outcome, RunResult
from injectkit.redact import Redactor
from injectkit.report import sanitize_url, write_atomic
from injectkit.report.json_report import SCHEMA_VERSION, report_schema, schema_text, to_json

RunFactory = Callable[..., RunResult]
ROOT = Path(__file__).resolve().parents[2]
FRAGMENT = "sk-live-ALPHA-9f3b"


def redactor_with(*values: str) -> Redactor:
    redactor = Redactor()
    for value in values:
        redactor.add(value, label="frag")
    return redactor


def test_output_has_schema_version_and_validates_against_the_schema(make_run: RunFactory) -> None:
    text = to_json(make_run(), Redactor(), target_url="https://api.example.test/chat")
    document = json.loads(text)
    assert document["schema_version"] == SCHEMA_VERSION == "1"
    jsonschema.validate(document, report_schema())


def test_published_schema_file_matches_the_models() -> None:
    published = (ROOT / "docs" / "report-schema.json").read_text(encoding="utf-8")
    assert published == schema_text()


def test_snapshot_of_a_fixed_run(make_run: RunFactory) -> None:
    text = to_json(make_run(), Redactor(), target_url="https://user:pw@api.example.test/chat?k=v")
    snapshot = (ROOT / "tests" / "data" / "report_snapshot.json").read_text(encoding="utf-8")
    assert text == snapshot


def test_output_is_deterministic_with_sorted_keys(make_run: RunFactory) -> None:
    run = make_run()
    first = to_json(run, Redactor())
    assert first == to_json(run, Redactor())
    keys = list(json.loads(first))
    assert keys == sorted(keys)


def test_secrets_anywhere_in_the_run_are_masked(make_run: RunFactory) -> None:
    run = make_run(
        evidence=f"leak {FRAGMENT} here",
        error_message=f"upstream said {FRAGMENT}",
        excerpt=f"body {FRAGMENT}",
    )
    redactor = redactor_with(FRAGMENT)
    text = to_json(
        run, redactor, target_url="https://api.example.test/chat", include_responses=True
    )
    assert FRAGMENT not in text
    assert "[REDACTED:frag]" in text


def test_url_userinfo_and_query_are_stripped(make_run: RunFactory) -> None:
    text = to_json(
        make_run(), Redactor(), target_url="https://user:hunter2@api.example.test:8443/chat?k=v#f"
    )
    url = json.loads(text)["target"]["url"]
    assert url == "https://api.example.test:8443/chat"
    assert "hunter2" not in text


def test_no_request_headers_or_bodies_are_reported(make_run: RunFactory) -> None:
    text = to_json(make_run(), Redactor()).lower()
    assert "authorization" not in text
    assert "headers" not in text
    assert "request_text" not in text


def test_responses_are_excluded_unless_requested(make_run: RunFactory) -> None:
    run = make_run(excerpt="the reply text")
    assert "the reply text" not in to_json(run, Redactor())
    included = json.loads(to_json(run, Redactor(), include_responses=True))
    excerpts = [r["response_excerpt"] for r in included["results"]]
    assert "the reply text" in excerpts


def test_report_states_that_no_indicator_is_not_proof_of_safety(make_run: RunFactory) -> None:
    disclaimer = json.loads(to_json(make_run(), Redactor()))["disclaimer"]
    assert "not evidence that the target is secure" in disclaimer


def test_summary_counts_match_results(make_run: RunFactory) -> None:
    document = json.loads(to_json(make_run(), Redactor()))
    assert document["summary"][Outcome.CONFIRMED.value] == 1
    assert sum(document["summary"].values()) == len(document["results"]) == 5


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://a.test/x?y=1", "https://a.test/x"),
        ("http://u:p@127.0.0.1:8000/chat", "http://127.0.0.1:8000/chat"),
        ("http://[::1]:9/c", "http://[::1]:9/c"),
    ],
)
def test_sanitize_url(url: str, expected: str) -> None:
    assert sanitize_url(url) == expected


def test_write_atomic_creates_and_replaces(tmp_path: Path) -> None:
    target = tmp_path / "out.json"
    write_atomic(target, "one\n")
    write_atomic(target, "two\n")
    assert target.read_text(encoding="utf-8") == "two\n"
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


def test_write_atomic_refuses_a_directory(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="not a regular file"):
        write_atomic(tmp_path, "x")


def test_write_atomic_refuses_a_missing_directory(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="does not exist"):
        write_atomic(tmp_path / "nope" / "out.json", "x")


def test_write_atomic_refuses_a_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real.json"
    real.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlinks need extra privileges on this Windows account")
    with pytest.raises(ReportError, match="not a regular file"):
        write_atomic(link, "x")
    assert real.read_text(encoding="utf-8") == "keep"
