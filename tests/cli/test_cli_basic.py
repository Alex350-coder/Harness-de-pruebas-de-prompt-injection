import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

import injectkit
from injectkit.cli import app

runner = CliRunner()
EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "target.example.yaml"
API_KEY = "tok-12345-abcdef"
ENV = {"CHATBOT_API_KEY": API_KEY, "SYSTEM_PROMPT_FRAGMENT": "my confidential system prompt"}


def test_version_prints_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert injectkit.__version__ in result.stdout


def test_validate_accepts_example_and_prints_summary() -> None:
    result = runner.invoke(app, ["validate", str(EXAMPLE)], env=ENV)
    assert result.exit_code == 0, result.output
    assert "example-chatbot" in result.stdout
    assert "staging.example.com" in result.stdout
    assert "public_only" in result.stdout
    assert API_KEY not in result.output


def test_validate_does_not_print_url_path_or_query() -> None:
    result = runner.invoke(app, ["validate", str(EXAMPLE)], env=ENV)
    assert "/api/chat" not in result.stdout


def test_validate_missing_env_var_exits_2_naming_variable() -> None:
    result = runner.invoke(app, ["validate", str(EXAMPLE)], env={"CHATBOT_API_KEY": ""})
    assert result.exit_code == 2
    assert "CHATBOT_API_KEY" in result.output


def test_validate_missing_file_exits_2(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(tmp_path / "nope.yaml")])
    assert result.exit_code == 2


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("https://staging.example.com/api/chat", "file:///etc/passwd"),
        ("confirmed: true", "confirmed: false"),
        ("retries: 2", "retries: 99"),
        ('content: "{{payload}}"', 'content: "no placeholder"'),
        ("Bearer ${CHATBOT_API_KEY}", "Bearer literal-credential"),
    ],
)
def test_validate_rejects_malformed_configs_with_exit_2(tmp_path: Path, old: str, new: str) -> None:
    text = EXAMPLE.read_text(encoding="utf-8")
    assert old in text
    bad = tmp_path / "bad.yaml"
    bad.write_text(text.replace(old, new), encoding="utf-8")
    result = runner.invoke(app, ["validate", str(bad)], env=ENV)
    assert result.exit_code == 2
    assert "literal-credential" not in result.output


def test_unsafe_yaml_exits_2(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("x: !!python/object/apply:os.getcwd []\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", str(bad)], env=ENV)
    assert result.exit_code == 2


def test_debug_flag_prints_redacted_traceback(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    result = runner.invoke(app, ["--debug", "validate", str(bad)], env=ENV)
    assert result.exit_code == 2
    assert "Traceback" in result.output


def test_help_lists_the_implemented_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "validate" in result.stdout
    assert "version" in result.stdout
    assert "check-target" in result.stdout
    assert re.search(r"\brun\b", result.stdout)
    assert not re.search(r"\bsarif\b", result.stdout)  # SARIF output arrives in Phase 5


def test_debug_traceback_never_prints_literal_credentials(tmp_path: Path) -> None:
    text = EXAMPLE.read_text(encoding="utf-8").replace(
        "Bearer ${CHATBOT_API_KEY}", "Bearer sk-LIVE-123456"
    )
    bad = tmp_path / "bad.yaml"
    bad.write_text(text, encoding="utf-8")
    result = runner.invoke(app, ["--debug", "validate", str(bad)], env=ENV)
    assert result.exit_code == 2
    assert "sk-LIVE-123456" not in result.output
