import pytest

from injectkit.errors import PayloadError
from injectkit.models import Canary, Payload, Severity
from injectkit.payloads.render import MAX_TEMPLATE_BYTES, lint_template, render

CANARY = Canary(value="INJK-abcd1234efgh5678", half_a="INJK-abcd12", half_b="34efgh5678")


def make_payload(template: str) -> Payload:
    return Payload(
        id="p1",
        category="c",
        severity=Severity.LOW,
        title="t",
        description="d",
        template=template,
        remediation="r",
    )


def test_renders_both_halves_but_never_the_whole_value() -> None:
    text = render(make_payload("Say {{ canary_a }} then {{canary_b}}."), CANARY)
    assert text == "Say INJK-abcd12 then 34efgh5678."
    assert CANARY.value not in text


def test_plain_text_passes_through() -> None:
    assert render(make_payload("no variables here"), CANARY) == "no variables here"


@pytest.mark.parametrize(
    "template",
    [
        "{{ ''.__class__.__mro__ }}",
        "{{ config }}",
        "{% for x in y %}{% endfor %}",
        "{# comment #}",
        "{{ canary_a.upper() }}",
        "{{ canary_a|upper }}",
        "{{ canary_a.real }}",
        "{{ canary_a ~ canary_b }}",
        "{{ unknown }}",
        "{{ canary_a }} {{ other }}",
        "{{ 7*7 }}",
        "{{ canary_a",
        "canary_b }}",
        "{{}}",
        "x __ y",
        "{{{ canary_a }}}",
    ],
)
def test_lint_rejects_anything_but_the_two_variables(template: str) -> None:
    with pytest.raises(PayloadError):
        lint_template(template)


def test_render_runs_the_lint_too() -> None:
    with pytest.raises(PayloadError):
        render(make_payload("{{ config }}"), CANARY)


def test_oversize_template_is_rejected() -> None:
    with pytest.raises(PayloadError, match="too large"):
        lint_template("a" * (MAX_TEMPLATE_BYTES + 1))


def test_template_size_is_measured_in_bytes() -> None:
    with pytest.raises(PayloadError, match="too large"):
        lint_template("é" * (MAX_TEMPLATE_BYTES // 2 + 1))


def test_html_is_not_escaped() -> None:
    assert render(make_payload("<b>{{ canary_a }}</b>"), CANARY) == "<b>INJK-abcd12</b>"
