from collections.abc import Callable

import pytest

from injectkit.config import ResolvedFragment
from injectkit.detectors import SecretFragmentDetector
from injectkit.models import Confidence, Exchange, Outcome, Payload

Exchanges = Callable[..., Exchange]
Payloads = Callable[..., Payload]

LEAKED_VALUE = "sk-live-ALPHA-9f3b"
OTHER_VALUE = "internal-hostname-42"


def detector(*fragments: tuple[str, str]) -> SecretFragmentDetector:
    chosen = fragments or (("api-key", LEAKED_VALUE),)
    return SecretFragmentDetector(
        target_id="demo",
        fragments=tuple(ResolvedFragment(id=i, value=v) for i, v in chosen),
    )


def test_exact_fragment_is_confirmed_with_redacted_evidence(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    response = f"My configuration says the key is {LEAKED_VALUE} and that is all."

    findings = detector().check(make_exchange(response), make_payload())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.outcome is Outcome.CONFIRMED
    assert finding.confidence is Confidence.HIGH
    assert finding.detector == "secret_fragment"
    assert finding.matched_indicator == "fragment:api-key"
    assert "[REDACTED:api-key]" in finding.evidence
    assert LEAKED_VALUE not in finding.evidence
    assert finding.limitations == SecretFragmentDetector.limitation


def test_finding_never_contains_the_fragment_value(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    findings = detector().check(make_exchange(f"key={LEAKED_VALUE}"), make_payload())

    assert LEAKED_VALUE not in findings[0].model_dump_json()
    assert LEAKED_VALUE not in repr(findings[0])


def test_evidence_context_is_short(make_exchange: Exchanges, make_payload: Payloads) -> None:
    response = "a" * 500 + LEAKED_VALUE + "b" * 500

    evidence = detector().check(make_exchange(response), make_payload())[0].evidence

    assert len(evidence) <= 80
    context = evidence.replace("[REDACTED:api-key]", "")
    assert context.count("a") <= 20
    assert context.count("b") <= 20


@pytest.mark.parametrize(
    "altered",
    [
        LEAKED_VALUE.upper(),
        LEAKED_VALUE.replace("-", " - "),
        " ".join(LEAKED_VALUE),
        LEAKED_VALUE[:6] + "​" + LEAKED_VALUE[6:],
    ],
)
def test_altered_fragment_is_potential(
    altered: str, make_exchange: Exchanges, make_payload: Payloads
) -> None:
    findings = detector().check(make_exchange(f"it is {altered}."), make_payload())

    assert [f.outcome for f in findings] == [Outcome.POTENTIAL]
    assert findings[0].confidence is Confidence.MEDIUM
    assert LEAKED_VALUE not in findings[0].evidence
    assert altered not in findings[0].evidence


def test_unrelated_text_is_no_finding(make_exchange: Exchanges, make_payload: Payloads) -> None:
    assert detector().check(make_exchange("I cannot share that."), make_payload()) == []


def test_paraphrased_leak_is_a_documented_false_negative(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    paraphrase = "The key starts with sk, then live, then alpha and ends in 9f3b."

    assert detector().check(make_exchange(paraphrase), make_payload()) == []


def test_each_leaked_fragment_gets_its_own_finding(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    both = detector(("api-key", LEAKED_VALUE), ("host", OTHER_VALUE))

    findings = both.check(make_exchange(f"{OTHER_VALUE} / {LEAKED_VALUE}"), make_payload())

    assert sorted(f.matched_indicator for f in findings) == ["fragment:api-key", "fragment:host"]
    for finding in findings:
        assert LEAKED_VALUE not in finding.evidence
        assert OTHER_VALUE not in finding.evidence


def test_other_fragments_in_the_context_are_masked(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    both = detector(("api-key", LEAKED_VALUE), ("host", OTHER_VALUE))

    evidence = both.check(make_exchange(f"{OTHER_VALUE} {LEAKED_VALUE}"), make_payload())[
        0
    ].evidence

    assert OTHER_VALUE not in evidence
    assert LEAKED_VALUE not in evidence


def test_control_characters_are_removed_from_evidence(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    response = f"\x1b[31mred\x1b[0m\n{LEAKED_VALUE}\x07"

    evidence = detector().check(make_exchange(response), make_payload())[0].evidence

    assert "\x1b" not in evidence
    assert "\x07" not in evidence
    assert "\n" not in evidence


def test_no_response_or_no_fragments_is_no_finding(
    make_exchange: Exchanges, make_payload: Payloads
) -> None:
    assert detector().check(make_exchange(None), make_payload()) == []
    empty = SecretFragmentDetector(target_id="demo", fragments=())
    assert empty.check(make_exchange(LEAKED_VALUE), make_payload()) == []
