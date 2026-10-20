import re
from collections import Counter
from importlib import resources

import pytest

from injectkit.models import Payload, Suite
from injectkit.payloads.canary import new_canary
from injectkit.payloads.loader import load_suite
from injectkit.payloads.render import render

CATEGORIES = {
    "direct_override",
    "system_prompt_extraction",
    "role_play",
    "delimiter_confusion",
    "instruction_smuggling",
    "canary_exfiltration",
    "output_format_abuse",
    "context_stuffing",
}
# Any scheme, "www." host or bare domain-like "//host.tld" reference.
EXTERNAL_REFERENCE = re.compile(r"[a-z][a-z0-9+.-]*://|\bwww\.|//[a-z0-9-]+\.[a-z]{2,}", re.I)


@pytest.fixture(scope="module")
def basic() -> Suite:
    return load_suite("basic")


def test_library_size_is_within_the_planned_range(basic: Suite) -> None:
    assert 28 <= len(basic.payloads) <= 34


def test_payload_ids_are_unique(basic: Suite) -> None:
    ids = [p.id for p in basic.payloads]
    assert len(ids) == len(set(ids))


def test_every_payload_is_marked_reviewed(basic: Suite) -> None:
    assert [p.id for p in basic.payloads if not p.reviewed] == []


def test_every_category_is_covered_at_least_twice(basic: Suite) -> None:
    counts = Counter(p.category for p in basic.payloads)
    assert set(counts) == CATEGORIES
    assert min(counts.values()) >= 2


def test_every_payload_has_complete_metadata(basic: Suite) -> None:
    for p in basic.payloads:
        assert p.title.strip(), p.id
        assert len(p.description.strip()) >= 20, p.id
        assert len(p.remediation.strip()) >= 20, p.id


def test_every_template_renders_in_the_sandbox_without_the_full_canary(basic: Suite) -> None:
    for p in basic.payloads:
        canary = new_canary()
        text = render(p, canary)
        assert canary.value not in text, p.id
        if "{{ canary_a }}" in p.template:
            assert canary.half_a in text, p.id


def uses_canary(p: Payload) -> bool:
    return "{{ canary_a }}" in p.template and "{{ canary_b }}" in p.template


def test_at_least_sixty_percent_use_both_canary_halves(basic: Suite) -> None:
    share = sum(uses_canary(p) for p in basic.payloads) / len(basic.payloads)
    assert share >= 0.6


def test_no_payload_references_an_external_address(basic: Suite) -> None:
    for p in basic.payloads:
        for text in (p.template, p.description, p.title, p.remediation):
            assert EXTERNAL_REFERENCE.search(text) is None, p.id


def test_payloads_do_not_contain_encoded_blobs(basic: Suite) -> None:
    blob = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    for p in basic.payloads:
        assert blob.search(p.template) is None, p.id


def test_every_library_file_records_its_reviewer_in_the_header() -> None:
    folder = resources.files("injectkit.payloads") / "data" / "suites" / "library"
    files = [f for f in folder.iterdir() if f.name.endswith(".yaml")]
    assert len(files) == len(CATEGORIES)
    for item in files:
        header = item.read_text(encoding="utf-8").splitlines()[:5]
        assert any(line.startswith("# reviewed_by:") for line in header), item.name


def test_severities_are_not_all_equal(basic: Suite) -> None:
    assert len({p.severity for p in basic.payloads}) >= 3
