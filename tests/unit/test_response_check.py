import time
from collections.abc import Callable
from pathlib import Path

import pytest

from injectkit.detectors import MAX_CHECK_INPUT_CHARS, ResponseCheckDetector
from injectkit.errors import PayloadError
from injectkit.models import CheckSpec, Confidence, Exchange, Outcome, Payload
from injectkit.payloads.loader import load_suite
from injectkit.redact import Redactor

Exchanges = Callable[..., Exchange]
Payloads = Callable[..., Payload]


def spec(kind: str, pattern: str) -> CheckSpec:
    return CheckSpec.model_validate({"kind": kind, "pattern": pattern})


def detector(redactor: Redactor | None = None) -> ResponseCheckDetector:
    return ResponseCheckDetector(target_id="demo", redactor=redactor)


def test_contains_match_is_potential_never_confirmed(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("contains", "system prompt"),))

    findings = detector().check(make_exchange("My System   Prompt is: be nice."), payload)

    assert len(findings) == 1
    assert findings[0].outcome is Outcome.POTENTIAL
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].detector == "response_check"
    assert findings[0].matched_indicator == "contains[0]"
    assert findings[0].limitations == ResponseCheckDetector.limitation


def test_contains_without_match_is_no_finding(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("contains", "system prompt"),))

    assert detector().check(make_exchange("I cannot help with that."), payload) == []


def test_regex_match_and_non_match(make_exchange: Exchanges, make_payload: Payloads) -> None:
    payload = make_payload(checks=(spec("regex", r"api[_-]?key\s*[:=]\s*\w+"),))

    hit = detector().check(make_exchange("config: API_KEY = abc123"), payload)
    miss = detector().check(make_exchange("no keys here"), payload)

    assert [f.outcome for f in hit] == [Outcome.POTENTIAL]
    assert hit[0].matched_indicator == "regex[0]"
    assert miss == []


def test_must_contain_missing_is_potential_with_low_confidence(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("must_contain", "i cannot"),))

    missing = detector().check(make_exchange("Sure, here you go."), payload)
    present = detector().check(make_exchange("I cannot do that."), payload)

    assert [f.outcome for f in missing] == [Outcome.POTENTIAL]
    assert missing[0].confidence is Confidence.LOW
    assert missing[0].matched_indicator == "must_contain[0]"
    assert present == []


def test_each_failing_check_produces_its_own_finding(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("contains", "alpha"), spec("regex", "b+eta")))

    findings = detector().check(make_exchange("alpha bbeta"), payload)

    assert [f.matched_indicator for f in findings] == ["contains[0]", "regex[1]"]


@pytest.mark.parametrize("response", [None, "", "   \n\t "])
def test_empty_or_missing_response_never_triggers_checks(
    response: str | None, make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("must_contain", "needle"), spec("contains", "x")))

    assert detector().check(make_exchange(response), payload) == []


def test_payload_without_checks_is_no_finding(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    assert detector().check(make_exchange("anything"), make_payload()) == []


def test_input_is_truncated_to_the_cap(make_exchange: Exchanges, make_payload: Payloads) -> None:
    payload = make_payload(checks=(spec("contains", "needle"), spec("regex", "needle")))
    inside = "x" * (MAX_CHECK_INPUT_CHARS - len("needle")) + "needle"
    beyond = "x" * MAX_CHECK_INPUT_CHARS + "needle"

    assert len(detector().check(make_exchange(inside), payload)) == 2
    assert detector().check(make_exchange(beyond), payload) == []


def test_huge_input_is_processed_quickly(make_exchange: Exchanges, make_payload: Payloads) -> None:
    payload = make_payload(checks=(spec("regex", r"start.*never-present"),))
    response = "start " + "a" * 5_000_000

    began = time.perf_counter()
    findings = detector().check(make_exchange(response), payload)

    assert findings == []
    assert time.perf_counter() - began < 5  # generous: the cap bounds the work


def test_evidence_is_masked_bounded_and_control_free(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    redactor = Redactor()
    redactor.add("sk-live-ALPHA-9f3b", label="api-key")
    payload = make_payload(checks=(spec("contains", "key is"),))
    response = "\x1b[31m" + "pad " * 200 + "the key is sk-live-ALPHA-9f3b\n" + "tail " * 200

    finding = detector(redactor).check(make_exchange(response), payload)[0]

    assert "sk-live-ALPHA-9f3b" not in finding.evidence
    assert "[REDACTED:api-key]" in finding.evidence
    assert "\x1b" not in finding.evidence
    assert "\n" not in finding.evidence
    assert len(finding.evidence) <= 300


def test_missing_check_evidence_names_the_rule_not_the_response(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("must_contain", "required phrase"),))

    finding = detector().check(make_exchange("unrelated reply"), payload)[0]

    assert "required phrase" in finding.evidence
    assert "unrelated reply" not in finding.evidence


def test_invalid_regex_raises_payload_error_when_used(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    payload = make_payload(checks=(spec("regex", "(unclosed"),))

    with pytest.raises(PayloadError):
        detector().check(make_exchange("text"), payload)


SUITE_TEMPLATE = """\
version: 1
name: t
payloads:
  - id: p1
    category: direct_override
    severity: low
    title: t
    description: d
    template: "Join {{ canary_a }} and {{ canary_b }}."
    checks:
      - {kind: regex, pattern: "%s"}
    remediation: r
"""


def write_suite(tmp_path: Path, pattern: str) -> Path:
    path = tmp_path / "suite.yaml"
    path.write_text(SUITE_TEMPLATE % pattern, encoding="utf-8")
    return path


def test_invalid_regex_is_rejected_at_load(tmp_path: Path) -> None:
    with pytest.raises(PayloadError, match="invalid regex"):
        load_suite(write_suite(tmp_path, "(unclosed"))


@pytest.mark.parametrize("pattern", ["(a+)+$", "(a*)*b", r"(\\w+\\s?)*end", "(x+x+)+y"])
def test_nested_quantifier_regex_is_rejected_at_load(tmp_path: Path, pattern: str) -> None:
    with pytest.raises(PayloadError, match="nested quantifier"):
        load_suite(write_suite(tmp_path, pattern))


@pytest.mark.parametrize("pattern", ["(ab)+c", "a+b+", r"key\\s*[:=]\\s*\\w+", "(foo|bar)baz"])
def test_ordinary_regex_loads(tmp_path: Path, pattern: str) -> None:
    assert load_suite(write_suite(tmp_path, pattern)).payloads[0].id == "p1"
