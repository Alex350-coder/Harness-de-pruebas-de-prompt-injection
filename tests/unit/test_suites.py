from pathlib import Path

import pytest

from injectkit.errors import PayloadError
from injectkit.payloads.loader import load_suite
from injectkit.runner import planned_requests

BASIC_COUNT = 32
QUICK_COUNT = 8


def test_basic_contains_every_library_payload() -> None:
    suite = load_suite("basic")

    assert suite.name == "basic"
    assert len(suite.payloads) == BASIC_COUNT
    assert suite.runs_per_payload == 1


def test_quick_is_a_small_subset_of_basic_covering_every_category() -> None:
    quick = load_suite("quick")
    basic = load_suite("basic")

    assert quick.name == "quick"
    assert len(quick.payloads) == QUICK_COUNT
    assert len(quick.payloads) <= 10
    assert {p.id for p in quick.payloads} <= {p.id for p in basic.payloads}
    assert {p.category for p in quick.payloads} == {p.category for p in basic.payloads}


def test_quick_payloads_equal_their_basic_definitions() -> None:
    basic = {p.id: p for p in load_suite("basic").payloads}

    for payload in load_suite("quick").payloads:
        assert payload == basic[payload.id]


def test_builtin_suites_are_all_reviewed() -> None:
    for name in ("basic", "quick"):
        assert all(p.reviewed for p in load_suite(name).payloads)


def test_builtin_suite_loading_does_not_depend_on_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)

    assert len(load_suite("basic").payloads) == BASIC_COUNT
    assert len(load_suite("quick").payloads) == QUICK_COUNT


def test_planned_request_counts_match_the_documented_sizes() -> None:
    assert planned_requests(load_suite("basic")) == BASIC_COUNT
    assert planned_requests(load_suite("quick")) == QUICK_COUNT


def test_loading_twice_gives_equal_suites() -> None:
    assert load_suite("basic") == load_suite("basic")


def test_unknown_builtin_suite_is_still_rejected() -> None:
    with pytest.raises(PayloadError, match="unknown built-in suite"):
        load_suite("standard")
