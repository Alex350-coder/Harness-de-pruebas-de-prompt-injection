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
