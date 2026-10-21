import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from injectkit.models import Outcome, RunResult
from injectkit.redact import Redactor
from injectkit.report.sarif import SARIF_VERSION, config_uri, to_sarif

RunFactory = Callable[..., RunResult]
DATA = Path(__file__).resolve().parents[1] / "data"
FRAGMENT = "sk-live-ALPHA-9f3b"
SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e"


def load_schema() -> dict[str, Any]:
    return json.loads((DATA / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))


def sarif(run: RunResult, redactor: Redactor | None = None, uri: str = "target.yaml") -> Any:
    return json.loads(to_sarif(run, redactor or Redactor(), config_uri=uri))


def test_vendored_schema_matches_the_recorded_checksum() -> None:
    digest = hashlib.sha256((DATA / "sarif-schema-2.1.0.json").read_bytes()).hexdigest()
    assert digest == SCHEMA_SHA256
    assert SCHEMA_SHA256 in (DATA / "sarif-schema-2.1.0.SOURCE.md").read_text(encoding="utf-8")


def test_output_validates_against_the_vendored_schema(make_run: RunFactory) -> None:
    document = sarif(make_run())
    jsonschema.Draft4Validator(load_schema()).validate(document)
    assert document["version"] == SARIF_VERSION == "2.1.0"


def test_empty_run_is_valid_and_has_no_results(make_run: RunFactory) -> None:
    run = make_run(outcomes=(Outcome.NO_INDICATOR, Outcome.ERROR))
    document = sarif(run)
    jsonschema.Draft4Validator(load_schema()).validate(document)
    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []


def test_only_confirmed_and_potential_become_results_with_mapped_levels(
    make_run: RunFactory,
) -> None:
    results = sarif(make_run())["runs"][0]["results"]
    assert [(r["properties"]["payload_id"], r["level"]) for r in results] == [
        ("p-1", "error"),
        ("p-2", "warning"),
    ]


def test_results_meet_github_code_scanning_requirements(make_run: RunFactory) -> None:
    run0 = sarif(make_run(), uri="examples/target.yaml")["runs"][0]
    rule_ids = {rule["id"] for rule in run0["tool"]["driver"]["rules"]}
    for rule in run0["tool"]["driver"]["rules"]:
        assert rule["shortDescription"]["text"]
        assert rule["fullDescription"]["text"]
        assert rule["help"]["text"]
        assert 0 < float(rule["properties"]["security-severity"]) <= 10
    for result in run0["results"]:
        assert result["ruleId"] in rule_ids
        assert result["message"]["text"]
        assert len(result["locations"]) == 1
        physical = result["locations"][0]["physicalLocation"]
        assert physical["artifactLocation"]["uri"] == "examples/target.yaml"
        assert physical["region"] == {
            "startLine": 1,
            "startColumn": 1,
            "endLine": 1,
            "endColumn": 1,
        }
        assert result["partialFingerprints"]["primaryLocationLineHash"]


def test_rule_ids_are_stable_one_per_category(make_run: RunFactory) -> None:
    rules = sarif(make_run())["runs"][0]["tool"]["driver"]["rules"]
    assert [rule["id"] for rule in rules] == ["injectkit/direct_override"]


def test_fingerprints_are_deterministic_and_do_not_depend_on_evidence(
    make_run: RunFactory,
) -> None:
    first = sarif(make_run(evidence="one"))["runs"][0]["results"]
    second = sarif(make_run(evidence="two"))["runs"][0]["results"]
    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in first]
    assert hashes == [r["partialFingerprints"]["primaryLocationLineHash"] for r in second]
    assert len(set(hashes)) == len(hashes)
    assert all(h.endswith(":1") for h in hashes)


def test_secrets_in_evidence_are_masked_everywhere(make_run: RunFactory) -> None:
    run = make_run(evidence=f"leak {FRAGMENT} here")
    redactor = Redactor()
    redactor.add(FRAGMENT, label="frag")
    text = to_sarif(run, redactor, config_uri="target.yaml")
    assert FRAGMENT not in text
    assert "[REDACTED" in text


def test_message_states_the_limitation(make_run: RunFactory) -> None:
    message = sarif(make_run())["runs"][0]["results"][0]["message"]["text"]
    assert "not data-theft proof" in message


def test_output_is_deterministic(make_run: RunFactory) -> None:
    run = make_run()
    assert to_sarif(run, Redactor(), config_uri="t.yaml") == to_sarif(
        run, Redactor(), config_uri="t.yaml"
    )


@pytest.mark.parametrize(
    "raw",
    [r"C:\Users\me\x.yaml", "../../etc/passwd", "", "file:///x", "a b?c#d"],
)
def test_config_uri_is_never_absolute_or_escaping(raw: str, tmp_path: Path) -> None:
    uri = config_uri(Path(raw), base=tmp_path)
    assert uri
    assert "\\" not in uri
    assert not uri.startswith(("/", ".."))
    assert ":" not in uri
    assert "?" not in uri
    assert "#" not in uri


def test_config_uri_is_relative_to_the_base(tmp_path: Path) -> None:
    config = tmp_path / "sub" / "t.yaml"
    config.parent.mkdir()
    config.write_text("x", encoding="utf-8")
    assert config_uri(config, base=tmp_path) == "sub/t.yaml"


@pytest.mark.parametrize(
    ("relative", "expected"),
    [
        (".github/injectkit.yaml", ".github/injectkit.yaml"),
        ("my config/t.yaml", "my%20config/t.yaml"),
        ("é.yaml", "%C3%A9.yaml"),
        ("a/b/t.yaml", "a/b/t.yaml"),
    ],
)
def test_config_uri_keeps_dot_directories_and_percent_encodes(
    relative: str, expected: str, tmp_path: Path
) -> None:
    assert config_uri(tmp_path / relative, base=tmp_path) == expected


def test_config_outside_the_base_is_reported_by_file_name_only(tmp_path: Path) -> None:
    base = tmp_path / "repo"
    base.mkdir()
    assert config_uri(tmp_path / "elsewhere" / "t.yaml", base=base) == "t.yaml"


def test_interrupted_run_is_marked_as_not_successful(make_run: RunFactory) -> None:
    run = make_run().model_copy(update={"interrupted": True})
    invocation = sarif(run)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False


def test_majority_error_run_is_not_successful_and_lists_notifications(
    make_run: RunFactory,
) -> None:
    run = make_run(outcomes=(Outcome.ERROR, Outcome.ERROR, Outcome.NO_INDICATOR))
    invocation = sarif(run)["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False
    notes = invocation["toolExecutionNotifications"]
    assert len(notes) == 2
    assert all(n["level"] == "error" and n["message"]["text"] for n in notes)


def test_exactly_half_errors_still_counts_as_successful(make_run: RunFactory) -> None:
    run = make_run(outcomes=(Outcome.ERROR, Outcome.NO_INDICATOR))
    assert sarif(run)["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_clean_run_has_no_notifications(make_run: RunFactory) -> None:
    invocation = sarif(make_run(outcomes=(Outcome.NO_INDICATOR,)))["runs"][0]["invocations"][0]
    assert "toolExecutionNotifications" not in invocation


def test_error_messages_in_notifications_are_masked(make_run: RunFactory) -> None:
    run = make_run(outcomes=(Outcome.ERROR,), error_message=f"upstream said {FRAGMENT}")
    redactor = Redactor()
    redactor.add(FRAGMENT, label="frag")
    assert FRAGMENT not in to_sarif(run, redactor, config_uri="t.yaml")


def test_distinct_indicators_for_the_same_payload_get_distinct_fingerprints(
    make_run: RunFactory,
) -> None:
    run = make_run(outcomes=(Outcome.CONFIRMED,))
    finding = run.results[0].findings[0]
    other = finding.model_copy(update={"matched_indicator": "other-indicator"})
    result = run.results[0].model_copy(update={"findings": (finding, other)})
    results = sarif(run.model_copy(update={"results": (result,)}))["runs"][0]["results"]
    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in results]
    assert len(set(hashes)) == 2


def test_identical_findings_get_increasing_occurrence_numbers(make_run: RunFactory) -> None:
    run = make_run(outcomes=(Outcome.CONFIRMED,))
    finding = run.results[0].findings[0]
    result = run.results[0].model_copy(update={"findings": (finding, finding)})
    results = sarif(run.model_copy(update={"results": (result,)}))["runs"][0]["results"]
    hashes = [r["partialFingerprints"]["primaryLocationLineHash"] for r in results]
    assert [h.rsplit(":", 1)[1] for h in hashes] == ["1", "2"]
    assert hashes[0].rsplit(":", 1)[0] == hashes[1].rsplit(":", 1)[0]


def test_driver_uses_version_not_semantic_version(make_run: RunFactory) -> None:
    driver = sarif(make_run())["runs"][0]["tool"]["driver"]
    assert driver["version"] == "0.1.0.dev0"
    assert "semanticVersion" not in driver


def test_control_characters_and_long_evidence_stay_valid_sarif(make_run: RunFactory) -> None:
    run = make_run(evidence="x\x00\x1b[31m\u202e" + "y" * 250)
    document = sarif(run)
    jsonschema.Draft4Validator(load_schema()).validate(document)
