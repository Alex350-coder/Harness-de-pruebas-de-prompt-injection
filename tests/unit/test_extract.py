import pytest

from injectkit.errors import TargetError
from injectkit.extract import MAX_PATH_CHARS, extract, validate_path
from injectkit.models import ErrorKind

OPENAI_LIKE = {"choices": [{"message": {"content": "hello"}}, {"message": {"content": "two"}}]}


def test_extracts_nested_key() -> None:
    assert extract({"a": {"b": "x"}}, "a.b") == "x"


def test_extracts_list_index() -> None:
    assert extract(OPENAI_LIKE, "choices.0.message.content") == "hello"
    assert extract(OPENAI_LIKE, "choices.1.message.content") == "two"


def test_digit_segment_is_a_key_on_dicts() -> None:
    assert extract({"0": "zero"}, "0") == "zero"


def test_empty_string_value_is_returned() -> None:
    assert extract({"a": ""}, "a") == ""


@pytest.mark.parametrize(
    ("obj", "path"),
    [
        ({"a": 1}, "b"),
        ({"a": {"b": 1}}, "a.c"),
        (OPENAI_LIKE, "choices.5.message.content"),
        (OPENAI_LIKE, "choices.x"),
        ({"a": "text"}, "a.b"),
        ({"a": None}, "a.b"),
        ([], "0"),
    ],
)
def test_missing_or_unreachable_is_extraction_error(obj: object, path: str) -> None:
    with pytest.raises(TargetError) as info:
        extract(obj, path)
    assert info.value.kind is ErrorKind.EXTRACTION


@pytest.mark.parametrize("value", [1, 1.5, True, None, ["a"], {"k": "v"}])
def test_non_string_result_is_extraction_error(value: object) -> None:
    with pytest.raises(TargetError) as info:
        extract({"a": value}, "a")
    assert info.value.kind is ErrorKind.EXTRACTION


def test_negative_index_is_rejected_not_wrapped() -> None:
    with pytest.raises(TargetError) as info:
        extract(OPENAI_LIKE, "choices.-1.message.content")
    assert info.value.kind is ErrorKind.EXTRACTION


def test_empty_path_is_extraction_error() -> None:
    with pytest.raises(TargetError) as info:
        extract({"a": "x"}, "")
    assert info.value.kind is ErrorKind.EXTRACTION


def test_error_does_not_leak_response_content() -> None:
    with pytest.raises(TargetError) as info:
        extract({"a": 12345678}, "a")
    assert "12345678" not in str(info.value)


@pytest.mark.parametrize("path", ["a", "a.b", "choices.0.message.content", "a-b.c_d"])
def test_validate_path_accepts_simple_paths(path: str) -> None:
    assert validate_path(path) == path


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "a.",
        ".a",
        "a..b",
        "a[0]",
        "a.*",
        "a b",
        "$.a",
        "a.b()",
        "a\n",
        "x" * (MAX_PATH_CHARS + 1),
    ],
)
def test_validate_path_rejects_expressions_and_bad_shapes(path: str) -> None:
    with pytest.raises(ValueError, match="path"):
        validate_path(path)
