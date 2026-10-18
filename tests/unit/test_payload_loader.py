from pathlib import Path

import pytest

from injectkit.errors import PayloadError
from injectkit.models import Severity
from injectkit.payloads.loader import MAX_PAYLOADS, MAX_SUITE_BYTES, load_suite

DATA = Path(__file__).parent.parent / "data" / "suites"


def payload_yaml(pid: str = "p1", template: str = "Say {{ canary_a }}{{ canary_b }}") -> str:
    return (
        f"  - id: {pid}\n"
        "    category: test\n"
        "    severity: low\n"
        "    title: T\n"
        "    description: D\n"
        f'    template: "{template}"\n'
        "    remediation: R\n"
    )


def write(tmp_path: Path, body: str, name: str = "suite.yaml") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def suite_text(*payloads: str, extra: str = "") -> str:
    return f"version: 1\nname: s\n{extra}payloads:\n" + "".join(payloads)


def test_loads_the_good_fixture() -> None:
    suite = load_suite(DATA / "good.yaml")
    assert suite.name == "good"
    assert [p.id for p in suite.payloads] == ["g-1", "g-2"]
    assert suite.payloads[0].severity is Severity.LOW
    assert suite.runs_per_payload == 2


def test_includes_inside_the_suite_directory_are_loaded() -> None:
    suite = load_suite(DATA / "with_include.yaml")
    assert [p.id for p in suite.payloads] == ["inline-1", "inc-1", "inc-2"]


@pytest.mark.parametrize(
    "target",
    ["../outside.yaml", "/etc/passwd", "sub/../../x.yaml", "C:/x.yaml", "..\\x.yaml", "a.txt"],
)
def test_bad_include_paths_are_rejected(tmp_path: Path, target: str) -> None:
    body = f"version: 1\nname: s\npayloads:\n  - include: '{target}'\n"
    with pytest.raises(PayloadError, match="include"):
        load_suite(write(tmp_path, body))


def test_include_symlink_escaping_the_directory_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.yaml").write_text(payload_yaml("evil"), encoding="utf-8")
    inside = tmp_path / "inside"
    inside.mkdir()
    link = inside / "link.yaml"
    try:
        link.symlink_to(outside / "x.yaml")
    except OSError:
        pytest.skip("symlinks not permitted on this system")
    body = "version: 1\nname: s\npayloads:\n  - include: link.yaml\n"
    with pytest.raises(PayloadError, match="include"):
        load_suite(write(inside, body))


@pytest.mark.parametrize(
    "template",
    ["{{ ''.__class__.__mro__ }}", "{{ config }}", "{% for x in y %}{% endfor %}", "{{ nope }}"],
)
def test_ssti_and_unknown_variables_are_rejected_at_load(tmp_path: Path, template: str) -> None:
    body = suite_text(payload_yaml(template=template))
    with pytest.raises(PayloadError):
        load_suite(write(tmp_path, body))


def test_more_than_the_payload_cap_is_rejected(tmp_path: Path) -> None:
    body = suite_text(*(payload_yaml(f"p{i}") for i in range(MAX_PAYLOADS + 1)))
    with pytest.raises(PayloadError, match="at most"):
        load_suite(write(tmp_path, body))


def test_exactly_the_payload_cap_is_accepted(tmp_path: Path) -> None:
    body = suite_text(*(payload_yaml(f"p{i}") for i in range(MAX_PAYLOADS)))
    assert len(load_suite(write(tmp_path, body)).payloads) == MAX_PAYLOADS


def test_duplicate_ids_are_rejected(tmp_path: Path) -> None:
    body = suite_text(payload_yaml("same"), payload_yaml("same"))
    with pytest.raises(PayloadError, match="duplicate"):
        load_suite(write(tmp_path, body))


@pytest.mark.parametrize("runs", [0, 6, -1])
def test_runs_per_payload_is_bounded(tmp_path: Path, runs: int) -> None:
    body = suite_text(payload_yaml(), extra=f"runs_per_payload: {runs}\n")
    with pytest.raises(PayloadError):
        load_suite(write(tmp_path, body))


def test_invalid_regex_check_is_rejected_at_load(tmp_path: Path) -> None:
    body = suite_text(payload_yaml() + "    checks:\n      - {kind: regex, pattern: '('}\n")
    with pytest.raises(PayloadError, match="regex"):
        load_suite(write(tmp_path, body))


def test_valid_regex_check_is_accepted(tmp_path: Path) -> None:
    body = suite_text(payload_yaml() + "    checks:\n      - {kind: regex, pattern: 'a+b'}\n")
    assert load_suite(write(tmp_path, body)).payloads[0].checks[0].pattern == "a+b"


def test_unknown_fields_are_rejected(tmp_path: Path) -> None:
    body = suite_text(payload_yaml() + "    surprise: 1\n")
    with pytest.raises(PayloadError):
        load_suite(write(tmp_path, body))


def test_oversize_file_is_rejected(tmp_path: Path) -> None:
    body = suite_text(payload_yaml()) + "# " + "x" * MAX_SUITE_BYTES + "\n"
    with pytest.raises(PayloadError, match="too large"):
        load_suite(write(tmp_path, body))


def test_non_mapping_document_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PayloadError):
        load_suite(write(tmp_path, "- just\n- a list\n"))


def test_unsafe_yaml_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(PayloadError):
        load_suite(write(tmp_path, "x: !!python/object/apply:os.system ['echo']\n"))


def test_missing_file_is_a_payload_error(tmp_path: Path) -> None:
    with pytest.raises(PayloadError):
        load_suite(tmp_path / "nope.yaml")


def test_unknown_builtin_name_is_a_payload_error() -> None:
    with pytest.raises(PayloadError, match="suite"):
        load_suite("definitely-not-a-suite")


@pytest.mark.parametrize("name", ["../x", "a/b", "A B", ""])
def test_builtin_names_are_restricted(name: str) -> None:
    with pytest.raises(PayloadError):
        load_suite(name)
