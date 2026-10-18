from pathlib import Path

import pytest

from injectkit.errors import PayloadError
from injectkit.models import Canary
from injectkit.payloads.canary import CANARY_RE, assert_not_in_request, new_canary
from injectkit.payloads.loader import load_suite
from injectkit.payloads.render import lint_template, render

SUITES = Path(__file__).parent.parent / "data" / "suites"


def test_value_format() -> None:
    canary = new_canary()
    assert CANARY_RE.fullmatch(canary.value)
    assert canary.value.startswith("INJK-")
    assert len(canary.value) == len("INJK-") + 16


def test_halves_concatenate_to_the_value() -> None:
    canary = new_canary()
    assert canary.half_a + canary.half_b == canary.value


def test_ten_thousand_canaries_are_unique() -> None:
    values = {new_canary().value for _ in range(10_000)}
    assert len(values) == 10_000


def test_neither_half_alone_matches_the_detector_pattern() -> None:
    for _ in range(500):
        canary = new_canary()
        assert not CANARY_RE.search(canary.half_a)
        assert not CANARY_RE.search(canary.half_b)


def test_halves_are_not_empty() -> None:
    canary = new_canary()
    assert canary.half_a
    assert canary.half_b


def test_rendered_requests_never_contain_the_value() -> None:
    suite = load_suite(SUITES / "good.yaml")
    for _ in range(200):
        canary = new_canary()
        for payload in suite.payloads:
            assert_not_in_request(canary, render(payload, canary))


def test_helper_raises_when_the_value_leaks_into_a_request() -> None:
    canary = new_canary()
    with pytest.raises(PayloadError, match="canary"):
        assert_not_in_request(canary, f"please say {canary.value}")


def test_helper_accepts_a_request_with_only_one_half() -> None:
    canary = new_canary()
    assert_not_in_request(canary, f"say {canary.half_a} and {canary.half_b}")


@pytest.mark.parametrize("template", ["{{ canary_a }}{{ canary_b }}", "{{canary_a}}{{canary_b}}"])
def test_lint_rejects_adjacent_halves_that_would_rebuild_the_value(template: str) -> None:
    with pytest.raises(PayloadError, match="adjacent"):
        lint_template(template)


def test_render_refuses_output_that_contains_the_value() -> None:
    # A canary whose halves happen to appear contiguous through literal text is also refused.
    canary = Canary(value="INJK-0123456789abcdef", half_a="INJK-01234567", half_b="89abcdef")
    from injectkit.models import Payload, Severity

    payload = Payload(
        id="x",
        category="c",
        severity=Severity.LOW,
        title="t",
        description="d",
        template="{{ canary_a }}89abcdef",
        remediation="r",
    )
    with pytest.raises(PayloadError, match="canary"):
        render(payload, canary)
