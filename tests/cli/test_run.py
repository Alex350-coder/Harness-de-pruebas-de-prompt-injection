import json
import re
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import respx
from click.testing import Result
from typer.testing import CliRunner

from injectkit import cli
from injectkit.cli import FailOn, app, exit_code_for
from injectkit.errors import ReportError
from injectkit.models import Outcome, RunResult

RunFactory = Callable[..., RunResult]
runner = CliRunner()
API_KEY = "tok-12345-abcdef"
ENV = {"TEST_API_KEY": API_KEY}
URL = "https://93.184.216.34/chat"
HALF_A = re.compile(r"INJK-[0-9a-f]{8}")
HALF_B = re.compile(r"\b[0-9a-f]{8}\b")
QUICK_SIZE = 8


def write_config(
    tmp_path: Path, *, url: str = URL, policy: str = "public_only", extra: str = ""
) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(
        f"""version: 1
authorization:
  confirmed: true
  scope_note: "tests"
name: demo
request:
  url: {url}
  headers:
    Authorization: "Bearer ${{TEST_API_KEY}}"
  body:
    messages:
      - role: user
        content: "{{{{payload}}}}"
response:
  path: reply
limits:
  timeout_seconds: 5
  requests_per_second: 50
  retries: 0
{extra}network:
  policy: {policy}
""",
        encoding="utf-8",
    )
    return path


def obedient(request: httpx.Request) -> httpx.Response:
    """Joins the two canary halves of any prompt: a maximally vulnerable target."""
    message: str = json.loads(request.content)["messages"][0]["content"]
    head = HALF_A.search(message)
    assert head is not None
    tail = HALF_B.search(message.replace(head.group(0), ""))
    assert tail is not None
    return httpx.Response(200, json={"reply": f"Done: {head.group(0)}{tail.group(0)}"})


def refusing(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"reply": "I cannot help with that."})


def invoke_run(tmp_path: Path, *args: str, extra: str = "") -> Result:
    return runner.invoke(
        app,
        ["run", str(write_config(tmp_path, extra=extra)), "--suite", "quick", *args],
        env=ENV,
    )


def test_vulnerable_target_exits_1_and_prints_the_console_report(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(URL).mock(side_effect=obedient)
        result = invoke_run(tmp_path)
    assert result.exit_code == 1, result.output
    assert route.call_count == QUICK_SIZE
    assert "Findings (8)" in result.stdout
    assert "No indicator" in result.stdout
    assert API_KEY not in result.output


def test_refusing_target_exits_0_and_still_says_it_proves_nothing(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path)
    assert result.exit_code == 0, result.output
    assert "Findings (0)" in result.stdout
    assert "not evidence that the target is safe" in result.stdout


def test_fail_on_never_exits_0_even_with_findings(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=obedient)
        result = invoke_run(tmp_path, "--fail-on", "never")
    assert result.exit_code == 0, result.output
    assert "Findings (8)" in result.stdout


def test_all_requests_failing_exits_3(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(return_value=httpx.Response(500, json={"error": "x"}))
        result = invoke_run(tmp_path)
    assert result.exit_code == 3, result.output
    assert "Errors (8)" in result.stdout


def test_policy_violation_is_an_error_result_and_sends_nothing(tmp_path: Path) -> None:
    config = write_config(tmp_path, url="http://127.0.0.1:9/chat")
    with respx.mock:
        route = respx.post("http://127.0.0.1:9/chat").mock(side_effect=refusing)
        result = runner.invoke(app, ["run", str(config), "--suite", "quick"], env=ENV)
    assert route.call_count == 0
    assert result.exit_code == 3
    assert "policy" in result.stdout
    assert API_KEY not in result.output


def test_bad_config_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    assert runner.invoke(app, ["run", str(bad)], env=ENV).exit_code == 2


def test_missing_env_var_exits_2(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(app, ["run", str(config)], env={"TEST_API_KEY": ""})
    assert result.exit_code == 2
    assert "TEST_API_KEY" in result.stderr


def test_unknown_suite_exits_2(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(app, ["run", str(config), "--suite", "nope"], env=ENV)
    assert result.exit_code == 2
    assert "unknown built-in suite" in result.stderr


def test_plan_over_max_requests_exits_2_and_sends_nothing(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--max-requests", "3")
    assert result.exit_code == 2
    assert route.call_count == 0
    assert "exceeds max_requests=3" in result.stderr


def test_cli_cannot_raise_the_config_cap(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--max-requests", "5000", extra="  max_requests: 4\n")
    assert result.exit_code == 2
    assert route.call_count == 0


def test_invalid_format_is_a_usage_error(tmp_path: Path) -> None:
    assert invoke_run(tmp_path, "--format", "xml").exit_code == 2


def test_dry_run_sends_zero_requests_and_prints_the_plan(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--dry-run")
    assert result.exit_code == 0, result.output
    assert route.call_count == 0
    assert "dry run: nothing was sent" in result.stdout
    assert f"planned requests:  {QUICK_SIZE}" in result.stdout
    assert "concurrency:" in result.stdout
    assert API_KEY not in result.output


def test_dry_run_still_refuses_an_oversized_plan(tmp_path: Path) -> None:
    result = invoke_run(tmp_path, "--dry-run", "--max-requests", "2")
    assert result.exit_code == 2


def test_json_format_prints_a_valid_report_to_stdout(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=obedient)
        result = invoke_run(tmp_path, "--format", "json")
    document = json.loads(result.stdout)
    assert document["schema_version"] == "1"
    assert document["summary"]["confirmed"] == QUICK_SIZE
    assert result.exit_code == 1


def test_output_writes_the_json_report_atomically(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--output", str(out))
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["schema_version"] == "1"
    assert "Findings (0)" in result.stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.json", "target.yaml"]


def test_unwritable_output_fails_before_any_request(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--output", str(tmp_path))
    assert result.exit_code == 2
    assert route.call_count == 0


def test_include_responses_adds_redacted_excerpts(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--output", str(out), "--include-responses")
    assert result.exit_code == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["results"][0]["response_excerpt"] == "I cannot help with that."


def test_non_default_policy_prints_a_warning_banner(tmp_path: Path) -> None:
    config = write_config(tmp_path, url="http://127.0.0.1:9/chat", policy="loopback")
    result = runner.invoke(app, ["run", str(config), "--suite", "quick", "--dry-run"], env=ENV)
    assert result.exit_code == 0
    assert "network policy 'loopback' allows non-public addresses" in result.stderr


def test_progress_is_not_written_when_stderr_is_not_a_tty(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path)
    assert result.stderr == ""


def test_ctrl_c_exits_130(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args: object, **kwargs: object) -> RunResult:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_execute", interrupt)
    assert invoke_run(tmp_path).exit_code == 130


def test_unexpected_exception_exits_3_with_a_one_line_message_without_its_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*args: object, **kwargs: object) -> RunResult:
        raise ValueError(f"boom {API_KEY}")

    monkeypatch.setattr(cli, "_execute", explode)
    result = invoke_run(tmp_path)
    assert result.exit_code == 3
    assert API_KEY not in result.output
    assert "ValueError" in result.stderr


@pytest.mark.parametrize(
    ("fail_on", "counts", "expected"),
    [
        (FailOn.CONFIRMED, {"confirmed": 1}, 1),
        (FailOn.CONFIRMED, {"potential": 2}, 0),
        (FailOn.POTENTIAL, {"potential": 1}, 1),
        (FailOn.POTENTIAL, {"no_indicator": 3}, 0),
        (FailOn.NEVER, {"confirmed": 4}, 0),
        (FailOn.NEVER, {"error": 3, "no_indicator": 1}, 3),
        (FailOn.CONFIRMED, {"error": 1, "no_indicator": 1}, 0),
        (FailOn.CONFIRMED, {"confirmed": 1, "error": 5}, 1),
    ],
)
def test_exit_code_matrix(
    make_run: RunFactory, fail_on: FailOn, counts: dict[str, int], expected: int
) -> None:
    outcomes = tuple(Outcome(name) for name, n in counts.items() for _ in range(n))
    assert exit_code_for(make_run(outcomes=outcomes), fail_on) == expected


def test_interrupted_run_maps_to_130(make_run: RunFactory) -> None:
    run = make_run().model_copy(update={"interrupted": True})
    assert exit_code_for(run, FailOn.NEVER) == 130


def test_exactly_half_errored_is_not_more_than_half(make_run: RunFactory) -> None:
    outcomes = (Outcome.ERROR, Outcome.ERROR, Outcome.NO_INDICATOR, Outcome.NO_INDICATOR)
    assert exit_code_for(make_run(outcomes=outcomes), FailOn.CONFIRMED) == 0


def test_just_over_half_errored_exits_3(make_run: RunFactory) -> None:
    outcomes = (Outcome.ERROR, Outcome.ERROR, Outcome.ERROR, Outcome.NO_INDICATOR)
    assert exit_code_for(make_run(outcomes=outcomes), FailOn.CONFIRMED) == 3


def test_an_empty_uninterrupted_run_exits_0(make_run: RunFactory) -> None:
    assert exit_code_for(make_run(outcomes=()), FailOn.CONFIRMED) == 0


def test_errors_produce_a_warning_with_the_count_on_stderr(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(return_value=httpx.Response(500, json={"error": "x"}))
        result = invoke_run(tmp_path)
    assert f"warning: {QUICK_SIZE} of {QUICK_SIZE} tests ended in an error" in result.stderr


def test_a_run_without_errors_prints_no_error_warning(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path)
    assert "tests ended in an error" not in result.stderr


def test_interrupted_partial_run_is_reported_and_exits_130(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_run: RunFactory
) -> None:
    partial = make_run().model_copy(update={"interrupted": True})
    monkeypatch.setattr(cli, "_execute", lambda *args, **kwargs: partial)
    out = tmp_path / "partial.json"
    result = invoke_run(tmp_path, "--output", str(out))
    assert result.exit_code == 130
    assert "interrupted" in result.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["run"]["interrupted"] is True


def test_report_is_printed_even_when_the_file_cannot_be_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing(path: Path, data: str) -> None:
        raise ReportError("could not write the report")

    monkeypatch.setattr(cli, "write_atomic", failing)
    with respx.mock:
        respx.post(URL).mock(side_effect=obedient)
        result = invoke_run(tmp_path, "--output", str(tmp_path / "r.json"))
    assert result.exit_code == 3
    assert "Findings (8)" in result.stdout
    assert "could not write the report" in result.stderr


def test_output_may_not_overwrite_the_config_file(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    original = config.read_text(encoding="utf-8")
    with respx.mock:
        route = respx.post(URL).mock(side_effect=refusing)
        result = runner.invoke(
            app, ["run", str(config), "--suite", "quick", "--output", str(config)], env=ENV
        )
    assert result.exit_code == 2
    assert route.call_count == 0
    assert config.read_text(encoding="utf-8") == original


def test_output_may_not_overwrite_a_suite_file(tmp_path: Path) -> None:
    suite = tmp_path / "mine.yml"
    suite.write_text("version: 1\nname: mine\npayloads: []\n", encoding="utf-8")
    config = write_config(tmp_path)
    result = runner.invoke(
        app, ["run", str(config), "--suite", str(suite), "--output", str(suite)], env=ENV
    )
    assert result.exit_code == 2


def test_yml_suites_are_treated_as_paths(tmp_path: Path) -> None:
    config = write_config(tmp_path)
    result = runner.invoke(
        app, ["run", str(config), "--suite", str(tmp_path / "absent.yml")], env=ENV
    )
    assert result.exit_code == 2
    assert "unknown built-in suite" not in result.stderr


def test_sarif_format_prints_valid_sarif_and_the_file_holds_sarif(tmp_path: Path) -> None:
    out = tmp_path / "injectkit.sarif"
    with respx.mock:
        respx.post(URL).mock(side_effect=obedient)
        result = invoke_run(tmp_path, "--format", "sarif", "--output", str(out))
    assert result.exit_code == 1, result.output
    document = json.loads(result.stdout)
    assert document["version"] == "2.1.0"
    assert len(document["runs"][0]["results"]) == QUICK_SIZE
    assert json.loads(out.read_text(encoding="utf-8")) == document
    assert API_KEY not in result.output


def test_sarif_clean_run_has_no_results_and_exits_zero(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(URL).mock(side_effect=refusing)
        result = invoke_run(tmp_path, "--format", "sarif", "--fail-on", "never")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["runs"][0]["results"] == []
