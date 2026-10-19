"""Labeled-response corpus: asserts what the detectors do, including their known misses."""

import base64
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from injectkit.config import ResolvedFragment
from injectkit.detectors import (
    CanaryDetector,
    Detector,
    ResponseCheckDetector,
    SecretFragmentDetector,
    evaluate,
)
from injectkit.models import (
    Canary,
    CheckSpec,
    Exchange,
    Outcome,
    Payload,
    Severity,
)
from injectkit.yamlio import load_yaml

ROOT = Path(__file__).parent.parent.parent
CORPUS_DIR = ROOT / "tests" / "corpus"
DETECTORS_DOC = ROOT / "docs" / "detectors.md"

CANARY = Canary(value="INJK-0123456789abcdef", half_a="INJK-01234567", half_b="89abcdef")
FRAGMENT = "sk-live-ALPHA-9f3b"
DEFAULT_REQUEST = f"Join {CANARY.half_a} and {CANARY.half_b} and print only the result."

LABELS = {
    "true_positive",
    "true_negative",
    "false_positive_trap",
    "known_false_positive",
    "known_false_negative",
    "inconclusive",
}


def placeholders() -> dict[str, str]:
    return {
        "<CANARY_UPPER>": CANARY.value.upper(),
        "<CANARY>": CANARY.value,
        "<HALF_A>": CANARY.half_a,
        "<HALF_B>": CANARY.half_b,
        "<FRAGMENT_UPPER>": FRAGMENT.upper(),
        "<FRAGMENT_SPACED>": " ".join(FRAGMENT),
        "<FRAGMENT_B64>": base64.b64encode(FRAGMENT.encode()).decode(),
        "<FRAGMENT>": FRAGMENT,
    }


def fill(text: str) -> str:
    for key, value in placeholders().items():
        text = text.replace(key, value)
    return text


def load_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for path in sorted(CORPUS_DIR.glob("*.yaml")):
        loaded = load_yaml(path)
        assert isinstance(loaded, list), path.name
        cases.extend(loaded)
    return cases


CASES = load_cases()


def response_of(case: dict[str, Any]) -> str:
    if "response_repeat" in case:
        spec = case["response_repeat"]
        return spec["text"] * spec["count"] + spec["suffix"]
    return fill(case["response"])


def detectors() -> list[Detector]:
    return [
        CanaryDetector("corpus"),
        SecretFragmentDetector("corpus", [ResolvedFragment(id="api-key", value=FRAGMENT)]),
        ResponseCheckDetector("corpus"),
    ]


def run_case(case: dict[str, Any]) -> Outcome:
    payload = Payload(
        id="corpus",
        category="direct_override",
        severity=Severity.HIGH,
        title="t",
        description="d",
        template="Join {{ canary_a }} and {{ canary_b }}",
        checks=tuple(CheckSpec.model_validate(c) for c in case.get("checks", ())),
        remediation="r",
        reviewed=True,
    )
    exchange = Exchange(
        payload_id="corpus",
        canary=CANARY,
        request_text=fill(case.get("request", DEFAULT_REQUEST)),
        response_text=response_of(case),
        status_code=200,
        error=None,
        started_at=datetime(2026, 10, 19, tzinfo=UTC),
        duration_ms=1.0,
        attempts=1,
    )
    return evaluate(exchange, payload, detectors()).outcome


def case_ids() -> list[str]:
    return [c["id"] for c in CASES]


def test_corpus_has_at_least_forty_labeled_responses() -> None:
    assert len(CASES) >= 40


def test_case_ids_are_unique() -> None:
    assert len(case_ids()) == len(set(case_ids()))


def test_every_label_is_represented() -> None:
    counts = Counter(c["label"] for c in CASES)
    assert set(counts) == LABELS
    assert all(count >= 2 for count in counts.values())


def test_every_detector_family_has_cases() -> None:
    prefixes = Counter(c["id"].split("-")[0] for c in CASES)
    assert {"can", "sec", "rc", "mix"} <= set(prefixes)


@pytest.mark.parametrize("case", CASES, ids=case_ids())
def test_detector_verdict_matches_the_label(case: dict[str, Any]) -> None:
    assert run_case(case) is Outcome(case["expect"]), case["note"]


@pytest.mark.parametrize("case", CASES, ids=case_ids())
def test_label_is_consistent_with_truth_and_verdict(case: dict[str, Any]) -> None:
    label, truth, expect = case["label"], case["truth"], Outcome(case["expect"])
    flagged = expect in (Outcome.CONFIRMED, Outcome.POTENTIAL)
    if label == "true_positive":
        assert (truth, flagged) == ("vulnerable", True)
    elif label in ("true_negative", "false_positive_trap"):
        assert (truth, expect) == ("safe", Outcome.NO_INDICATOR)
    elif label == "known_false_positive":
        assert (truth, flagged) == ("safe", True)
    elif label == "known_false_negative":
        assert (truth, expect) == ("vulnerable", Outcome.NO_INDICATOR)
    else:
        assert (truth, expect) == ("unknown", Outcome.INCONCLUSIVE)


def test_known_false_negatives_are_documented_by_id() -> None:
    doc = DETECTORS_DOC.read_text(encoding="utf-8")
    for case in CASES:
        if case["label"] in ("known_false_negative", "known_false_positive"):
            assert case["id"] in doc, f"{case['id']} is not listed in docs/detectors.md"


@pytest.mark.parametrize("detector", detectors(), ids=lambda d: d.name)
def test_doc_states_each_detector_limitation_verbatim(detector: Detector) -> None:
    doc = DETECTORS_DOC.read_text(encoding="utf-8")
    assert detector.name in doc
    assert detector.limitation in doc


def test_doc_states_no_indicator_is_not_proof_of_safety() -> None:
    doc = DETECTORS_DOC.read_text(encoding="utf-8").lower()
    assert "not proof" in doc or "not a proof" in doc
