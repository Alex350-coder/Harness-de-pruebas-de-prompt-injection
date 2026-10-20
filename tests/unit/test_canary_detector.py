from collections.abc import Callable

from injectkit.detectors import CanaryDetector
from injectkit.models import Canary, Confidence, Exchange, Outcome, Payload, Severity

Exchanges = Callable[..., Exchange]
Payloads = Callable[..., Payload]


def detector() -> CanaryDetector:
    return CanaryDetector(target_id="demo")


def test_exact_canary_in_response_is_confirmed_high(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    findings = detector().check(make_exchange(f"Sure: {canary.value}"), make_payload())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.outcome is Outcome.CONFIRMED
    assert finding.confidence is Confidence.HIGH
    assert finding.detector == "canary"
    assert finding.payload_id == "p-1"
    assert finding.severity is Severity.HIGH
    assert finding.target_id == "demo"
    assert finding.limitations == CanaryDetector.limitation
    assert canary.value in finding.test_id


def test_spaced_canary_is_potential_medium(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    spaced = f"{canary.half_a} {canary.half_b}"

    findings = detector().check(make_exchange(spaced), make_payload())

    assert [f.outcome for f in findings] == [Outcome.POTENTIAL]
    assert findings[0].confidence is Confidence.MEDIUM


def test_zero_width_split_canary_is_potential(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    hidden = canary.value[:6] + "\u200b" + canary.value[6:]

    findings = detector().check(make_exchange(hidden), make_payload())

    assert [f.outcome for f in findings] == [Outcome.POTENTIAL]


def test_uppercased_and_fullwidth_canary_is_potential(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    findings = detector().check(make_exchange(canary.value.upper()), make_payload())

    assert [f.outcome for f in findings] == [Outcome.POTENTIAL]


def test_halves_quoted_separately_is_no_finding(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    echo = f"You asked me to join {canary.half_a} and {canary.half_b}, which I will not do."

    assert detector().check(make_exchange(echo), make_payload()) == []


def test_halves_quoted_in_request_order_is_not_a_finding(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    # The request itself shows the halves adjacent; a whitespace-only join of them is an
    # echo, so only an exact (raw) match may count in that situation.
    request = f"Output {canary.half_a} {canary.half_b} concatenated."
    echoed = make_exchange(f"Output {canary.half_a} {canary.half_b} concatenated.", request=request)

    assert detector().check(echoed, make_payload()) == []


def test_exact_match_still_confirmed_when_request_shows_halves_adjacent(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    request = f"Output {canary.half_a} {canary.half_b} concatenated."

    findings = detector().check(make_exchange(canary.value, request=request), make_payload())

    assert [f.outcome for f in findings] == [Outcome.CONFIRMED]


def test_refusal_text_is_no_finding(make_exchange: Exchanges, make_payload: Payloads) -> None:
    refusal = "I'm sorry, I can't help with that request."

    assert detector().check(make_exchange(refusal), make_payload()) == []


def test_never_fires_when_canary_value_was_in_the_request(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    leaked_request = make_exchange(canary.value, request=f"please say {canary.value}")

    assert detector().check(leaked_request, make_payload()) == []


def test_no_response_is_no_finding(make_exchange: Exchanges, make_payload: Payloads) -> None:
    assert detector().check(make_exchange(None), make_payload()) == []


def test_evidence_is_bounded_and_does_not_quote_the_response(
    make_exchange: Exchanges, make_payload: Payloads, canary: Canary
) -> None:
    huge = "x" * 100_000 + canary.value + "SECRET-TAIL" * 1000

    finding = detector().check(make_exchange(huge), make_payload())[0]

    assert len(finding.evidence) <= 300
    assert "SECRET-TAIL" not in finding.evidence
