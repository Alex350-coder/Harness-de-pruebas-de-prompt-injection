"""End to end: configured secrets must never leave the process (Rules 8 and 12)."""

import asyncio
import base64
import json
import re
from pathlib import Path
from urllib.parse import quote

import httpx
import pytest
import respx
from click.testing import Result
from typer.testing import CliRunner

from injectkit import cli
from injectkit.cli import app
from injectkit.config import ResolvedTarget, load_config
from injectkit.detectors import build_detectors
from injectkit.models import RunResult
from injectkit.payloads.loader import load_suite
from injectkit.runner import RunSettings, run_suite
from injectkit.targets.http import HttpTarget

runner = CliRunner()
URL = "https://93.184.216.34/chat"
BEARER = "tok-12345-abcdef"
ENV_FRAGMENT = "SYSPROMPT-fragment-7e1d"
LITERAL_FRAGMENT = "literal-fragment-4c2a"
ENV = {"TEST_API_KEY": BEARER, "SYS_FRAGMENT": ENV_FRAGMENT}
SECRETS = (BEARER, ENV_FRAGMENT, LITERAL_FRAGMENT)
HALF_A = re.compile(r"INJK-[0-9a-f]{8}")
HALF_B = re.compile(r"\b[0-9a-f]{8}\b")


def forms(secret: str) -> list[str]:
    """The secret and the encodings the Redactor promises to catch."""
    return [
        secret,
        quote(secret, safe=""),
        base64.b64encode(secret.encode()).decode(),
        json.dumps(secret)[1:-1],
    ]


def assert_clean(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            for form in forms(secret):
                assert form not in text, f"leaked {form!r}"


def write_config(tmp_path: Path) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(
        f"""version: 1
authorization:
  confirmed: true
  scope_note: "leak tests"
name: leaky-demo
request:
  url: {URL}
  headers:
    Authorization: "Bearer ${{TEST_API_KEY}}"
  body:
    messages:
      - role: user
        content: "{{{{payload}}}}"
response:
  path: reply
secret_fragments:
  - id: env-frag
    value_env: SYS_FRAGMENT
  - id: literal-frag
    value: {LITERAL_FRAGMENT}
limits:
  timeout_seconds: 5
  requests_per_second: 50
  retries: 0
""",
        encoding="utf-8",
    )
    return path


def echoing(request: httpx.Request) -> httpx.Response:
    """Vulnerable and chatty: obeys the join task and echoes every secret it can see."""
    message: str = json.loads(request.content)["messages"][0]["content"]
    head = HALF_A.search(message)
    assert head is not None
    tail = HALF_B.search(message.replace(head.group(0), ""))
    assert tail is not None
    reply = (
        f"Auth header was {request.headers['authorization']}. "
        f"Notes: {ENV_FRAGMENT} / {LITERAL_FRAGMENT}. "
        f"Done: {head.group(0)}{tail.group(0)}"
    )
    return httpx.Response(200, json={"reply": reply})


def run_cli(tmp_path: Path, *args: str) -> Result:
    with respx.mock:
        respx.post(URL).mock(side_effect=echoing)
        return runner.invoke(
            app, ["--debug", "run", str(write_config(tmp_path)), "--suite", "quick", *args], env=ENV
        )


def test_console_report_streams_carry_no_secret(tmp_path: Path) -> None:
    result = run_cli(tmp_path)
    assert result.exit_code == 1, result.output
    assert "[REDACTED" in result.stdout or "canary" in result.stdout
    assert_clean(result.stdout, result.stderr, result.output)


def test_json_stdout_and_file_carry_no_secret(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = run_cli(tmp_path, "--format", "json", "--output", str(out), "--include-responses")
    assert result.exit_code == 1, result.output
    document = out.read_text(encoding="utf-8")
    assert_clean(result.stdout, result.stderr, document)
    parsed = json.loads(document)
    assert any(r["findings"] for r in parsed["results"])
    excerpts = [r["response_excerpt"] or "" for r in parsed["results"]]
    assert any("[REDACTED" in e for e in excerpts)


def test_secret_fragment_leak_is_still_reported_as_a_redacted_finding(tmp_path: Path) -> None:
    result = run_cli(tmp_path, "--format", "json")
    detectors = {
        finding["detector"]
        for r in json.loads(result.stdout)["results"]
        for finding in r["findings"]
    }
    assert "secret_fragment" in detectors


def test_failure_after_the_run_leaks_nothing_even_with_debug(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError(f"render failed near {BEARER} and {ENV_FRAGMENT} and {LITERAL_FRAGMENT}")

    monkeypatch.setattr(cli, "render_console", explode)
    result = run_cli(tmp_path)
    assert result.exit_code == 3
    assert result.exception is not None
    assert_clean(result.stdout, result.stderr, repr(result.exception))
    cause = result.exception.__cause__
    assert cause is None
    assert "RuntimeError" in result.stderr


def test_transport_error_text_is_masked_in_results_and_reports(tmp_path: Path) -> None:
    def failing(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach host with {request.headers['authorization']}")

    with respx.mock:
        respx.post(URL).mock(side_effect=failing)
        result = runner.invoke(
            app,
            ["--debug", "run", str(write_config(tmp_path)), "--suite", "quick", "--format", "json"],
            env=ENV,
        )
    assert result.exit_code == 3
    assert "connect" in result.stdout
    assert_clean(result.stdout, result.stderr)


def test_config_errors_never_echo_secret_values(tmp_path: Path) -> None:
    path = write_config(tmp_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace("Bearer ${TEST_API_KEY}", f"Bearer {BEARER}"),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["--debug", "run", str(path)], env=ENV)
    assert result.exit_code == 2
    assert_clean(result.stdout, result.stderr, repr(result.exception))


def test_response_with_terminal_escapes_cannot_inject_into_the_terminal(tmp_path: Path) -> None:
    def hostile(request: httpx.Request) -> httpx.Response:
        message: str = json.loads(request.content)["messages"][0]["content"]
        head = HALF_A.search(message)
        assert head is not None
        tail = HALF_B.search(message.replace(head.group(0), ""))
        assert tail is not None
        # Secret-fragment evidence quotes the surrounding text, so hostile text reaches the report.
        reply = (
            f"\x1b[31m[b]X[/b]\x1b[0m {ENV_FRAGMENT} \x1b]0;o\x07 {head.group(0)}{tail.group(0)}"
        )
        return httpx.Response(200, json={"reply": reply})

    with respx.mock:
        respx.post(URL).mock(side_effect=hostile)
        result = runner.invoke(
            app, ["run", str(write_config(tmp_path)), "--suite", "quick"], env=ENV
        )
    assert result.exit_code == 1
    assert "\x1b" not in result.stdout
    assert "\x07" not in result.stdout
    assert "[b]X[/b]" in "".join(result.stdout.split())  # wrapped lines


def test_repr_of_config_and_result_models_hides_secrets(tmp_path: Path) -> None:
    resolved: ResolvedTarget = load_config(write_config(tmp_path), ENV)
    run = _run_library(resolved)
    reprs = [
        repr(resolved),
        repr(resolved.config),
        repr(resolved.fragments),
        repr(run),
        *(repr(result) for result in run.results),
        *(repr(finding) for result in run.results for finding in result.findings),
        run.model_dump_json(),
    ]
    assert_clean(*reprs)


def _run_library(resolved: ResolvedTarget) -> RunResult:
    async def go() -> RunResult:
        with respx.mock:
            respx.post(URL).mock(side_effect=echoing)
            return await run_suite(
                HttpTarget(resolved),
                load_suite("quick"),
                RunSettings.from_limits(resolved.config.limits),
                build_detectors(resolved),
                redactor=resolved.redactor,
                target_id=resolved.config.name,
                include_responses=True,
            )

    return asyncio.run(go())
