import pytest

from injectkit.detectors import normalize, squash


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("INJK-ABC", "injk-abc"),  # mixed case
        ("IN\u200bJK\u200d-abc", "injk-abc"),  # zero-width space / joiner (Cf) removed
        ("\uff29\uff2e\uff2a\uff2b\uff0d\uff41\uff42\uff43", "injk-abc"),  # fullwidth forms (NFKC)
        ("injk\u00a0-\u00a0abc", "injk - abc"),  # NBSP becomes a normal space
        ("a \t\n  b", "a b"),  # whitespace collapsed
        ("\ufeffstart", "start"),  # BOM is Cf
        ("Stra\u00dfe", "strasse"),  # casefold, not lower
        ("", ""),
    ],
)
def test_normalize_known_cases(raw: str, expected: str) -> None:
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "\uff29\uff2e\uff2a\uff2b \u200b x",
        "\u01c5 \ufb03 \u1e9e",
        "\u2126 \u212b K",
        "a\u0345\u03a3 b",
        "  A  b\u00a0C  ",
    ],
)
def test_normalize_is_idempotent(raw: str) -> None:
    once = normalize(raw)
    assert normalize(once) == once


def test_squash_removes_all_whitespace() -> None:
    assert squash("IN JK-\u200b12 34\n") == "injk-1234"


def test_normalize_does_not_leave_zero_width_characters() -> None:
    assert "\u200b" not in normalize("a\u200bb")
