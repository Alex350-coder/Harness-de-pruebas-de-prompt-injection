from pathlib import Path

import pytest

from injectkit.config import load_config
from injectkit.errors import ConfigError

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "target.example.yaml"
API_KEY = "tok-12345-abcdef"
FRAGMENT = "my confidential system prompt"
ENV = {"CHATBOT_API_KEY": API_KEY, "SYSTEM_PROMPT_FRAGMENT": FRAGMENT}


def test_example_config_loads_with_dummy_env() -> None:
    resolved = load_config(EXAMPLE, env=ENV)
    assert resolved.config.name == "example-chatbot"
    assert resolved.headers["Authorization"] == f"Bearer {API_KEY}"
    assert resolved.fragments[0].id == "sys-1"


def test_resolved_secrets_are_registered_with_redactor() -> None:
    resolved = load_config(EXAMPLE, env=ENV)
    masked = resolved.redactor.mask(f"Authorization: Bearer {API_KEY} / {FRAGMENT}")
    assert API_KEY not in masked
    assert FRAGMENT not in masked
    assert "[REDACTED:sys-1]" in masked


def test_missing_env_var_names_the_variable_not_a_value() -> None:
    with pytest.raises(ConfigError) as info:
        load_config(EXAMPLE, env={"SYSTEM_PROMPT_FRAGMENT": FRAGMENT})
    message = str(info.value)
    assert "CHATBOT_API_KEY" in message
    assert FRAGMENT not in message


def test_empty_env_var_is_treated_as_missing() -> None:
    with pytest.raises(ConfigError, match="CHATBOT_API_KEY"):
        load_config(EXAMPLE, env={"CHATBOT_API_KEY": "", "SYSTEM_PROMPT_FRAGMENT": FRAGMENT})


def test_env_fragment_shorter_than_minimum_is_rejected_without_leaking_it() -> None:
    env = {"CHATBOT_API_KEY": API_KEY, "SYSTEM_PROMPT_FRAGMENT": "abc"}
    with pytest.raises(ConfigError) as info:
        load_config(EXAMPLE, env=env)
    assert "abc" not in str(info.value).replace("at least", "")


def test_repr_does_not_expose_secrets() -> None:
    resolved = load_config(EXAMPLE, env=ENV)
    text = repr(resolved)
    assert API_KEY not in text
    assert FRAGMENT not in text


def test_yaml_with_unsafe_tag_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: !!python/object/apply:os.getcwd []\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, env=ENV)


def test_non_mapping_document_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(path, env=ENV)


def test_defaults_to_process_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CHATBOT_API_KEY", API_KEY)
    monkeypatch.setenv("SYSTEM_PROMPT_FRAGMENT", FRAGMENT)
    assert load_config(EXAMPLE).headers["Authorization"].endswith(API_KEY)


def test_resolved_header_with_control_characters_is_rejected() -> None:
    env = {"CHATBOT_API_KEY": "tok-12345\r\nX-Evil: 1", "SYSTEM_PROMPT_FRAGMENT": FRAGMENT}
    with pytest.raises(ConfigError, match="Authorization") as info:
        load_config(EXAMPLE, env=env)
    assert "tok-12345" not in str(info.value)


def test_very_short_env_secret_is_rejected() -> None:
    env = {"CHATBOT_API_KEY": "a", "SYSTEM_PROMPT_FRAGMENT": FRAGMENT}
    with pytest.raises(ConfigError, match="CHATBOT_API_KEY"):
        load_config(EXAMPLE, env=env)
