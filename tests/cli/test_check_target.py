import json
from pathlib import Path

import httpx
import respx
from typer.testing import CliRunner

from injectkit.check import BENIGN_MESSAGE, MAX_SHOWN_CHARS
from injectkit.cli import app

runner = CliRunner()
API_KEY = "tok-12345-abcdef"
ENV = {"TEST_API_KEY": API_KEY}
LOOPBACK_URL = "http://127.0.0.1:8000/chat"
PUBLIC_URL = "https://93.184.216.34/chat"


def write_config(tmp_path: Path, url: str = PUBLIC_URL, policy: str = "public_only") -> Path:
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
network:
  policy: {policy}
""",
        encoding="utf-8",
    )
    return path


def reply(text: str) -> httpx.Response:
    return httpx.Response(200, json={"reply": text})


def test_success_exits_0_and_reports_status_latency_and_length_only(tmp_path: Path) -> None:
    with respx.mock:
        route = respx.post(PUBLIC_URL).mock(return_value=reply("hello there"))
        result = runner.invoke(app, ["check-target", str(write_config(tmp_path))], env=ENV)
    assert result.exit_code == 0, result.output
    assert "status: 200" in result.output
    assert "latency:" in result.output
    assert "response length: 11" in result.output
    assert "hello there" not in result.output
    assert API_KEY not in result.output
    assert route.call_count == 1
    sent = json.loads(route.calls.last.request.content)
    assert sent["messages"][0]["content"] == BENIGN_MESSAGE


def test_show_response_prints_redacted_truncated_sanitized_text(tmp_path: Path) -> None:
    body = f"key={API_KEY} \x1b[31mred\x1b[0m " + "x" * 1000
    with respx.mock:
        respx.post(PUBLIC_URL).mock(return_value=reply(body))
        result = runner.invoke(
            app, ["check-target", str(write_config(tmp_path)), "--show-response"], env=ENV
        )
    assert result.exit_code == 0, result.output
    assert API_KEY not in result.output
    assert "[REDACTED]" in result.output
    assert "\x1b" not in result.output
    assert "x" * (MAX_SHOWN_CHARS + 1) not in result.output
    assert "truncated" in result.output


def test_policy_blocked_url_exits_2_without_any_request(tmp_path: Path) -> None:
    config = write_config(tmp_path, url=LOOPBACK_URL, policy="public_only")
    with respx.mock:
        route = respx.post(LOOPBACK_URL).mock(return_value=reply("x"))
        result = runner.invoke(app, ["check-target", str(config)], env=ENV)
    assert result.exit_code == 2
    assert route.call_count == 0
    assert "policy" in result.output


def test_metadata_address_is_blocked_even_in_private_mode(tmp_path: Path) -> None:
    config = write_config(tmp_path, url="http://169.254.169.254/latest", policy="private")
    with respx.mock:
        route = respx.route(host="169.254.169.254").mock(return_value=reply("x"))
        result = runner.invoke(app, ["check-target", str(config)], env=ENV)
    assert result.exit_code == 2
    assert route.call_count == 0


def test_timeout_exits_3(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(PUBLIC_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        result = runner.invoke(app, ["check-target", str(write_config(tmp_path))], env=ENV)
    assert result.exit_code == 3
    assert "timeout" in result.output


def test_http_error_exits_3(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(PUBLIC_URL).mock(return_value=httpx.Response(500))
        result = runner.invoke(app, ["check-target", str(write_config(tmp_path))], env=ENV)
    assert result.exit_code == 3
    assert "500" in result.output


def test_extraction_failure_exits_3(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(PUBLIC_URL).mock(return_value=httpx.Response(200, json={"other": "x"}))
        result = runner.invoke(app, ["check-target", str(write_config(tmp_path))], env=ENV)
    assert result.exit_code == 3
    assert "extraction" in result.output


def test_loopback_and_private_modes_print_a_warning(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(LOOPBACK_URL).mock(return_value=reply("ok"))
        loopback = runner.invoke(
            app, ["check-target", str(write_config(tmp_path, LOOPBACK_URL, "loopback"))], env=ENV
        )
    assert loopback.exit_code == 0, loopback.output
    assert "warning" in loopback.output.lower()
    assert "loopback" in loopback.output
    with respx.mock:
        respx.post("http://10.1.2.3/chat").mock(return_value=reply("ok"))
        private = runner.invoke(
            app,
            ["check-target", str(write_config(tmp_path, "http://10.1.2.3/chat", "private"))],
            env=ENV,
        )
    assert private.exit_code == 0, private.output
    assert "warning" in private.output.lower()


def test_public_only_mode_prints_no_warning(tmp_path: Path) -> None:
    with respx.mock:
        respx.post(PUBLIC_URL).mock(return_value=reply("ok"))
        result = runner.invoke(app, ["check-target", str(write_config(tmp_path))], env=ENV)
    assert "warning" not in result.output.lower()


def test_invalid_config_exits_2(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\n", encoding="utf-8")
    result = runner.invoke(app, ["check-target", str(path)], env=ENV)
    assert result.exit_code == 2


def test_missing_env_var_exits_2_naming_it(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["check-target", str(write_config(tmp_path))], env={"TEST_API_KEY": ""}
    )
    assert result.exit_code == 2
    assert "TEST_API_KEY" in result.output
