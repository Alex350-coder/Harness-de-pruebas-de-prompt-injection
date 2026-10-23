import copy
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from injectkit.config import TargetConfig, parse_config
from injectkit.errors import ConfigError

VALID: dict[str, Any] = {
    "version": 1,
    "authorization": {"confirmed": True, "scope_note": "Own staging app"},
    "name": "my-chatbot",
    "request": {
        "url": "https://staging.example.com/api/chat",
        "method": "POST",
        "headers": {
            "Authorization": "Bearer ${CHATBOT_API_KEY}",
            "Content-Type": "application/json",
        },
        "body": {"messages": [{"role": "user", "content": "{{payload}}"}]},
    },
    "response": {"path": "choices.0.message.content", "max_bytes": 1048576},
    "secret_fragments": [{"id": "sys-1", "value_env": "SYSTEM_PROMPT_FRAGMENT"}],
    "limits": {
        "timeout_seconds": 30,
        "concurrency": 4,
        "requests_per_second": 2.0,
        "retries": 2,
        "max_requests": 500,
    },
    "network": {"policy": "public_only", "follow_redirects": False, "max_redirects": 3},
}


def mutated(change: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    data = copy.deepcopy(VALID)
    change(data)
    return data


def _set(path: list[str | int], value: Any) -> Callable[[dict[str, Any]], None]:
    def apply(data: dict[str, Any]) -> None:
        node: Any = data
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return apply


def _delete(path: list[str | int]) -> Callable[[dict[str, Any]], None]:
    def apply(data: dict[str, Any]) -> None:
        node: Any = data
        for key in path[:-1]:
            node = node[key]
        del node[path[-1]]

    return apply


NEGATIVE_CASES: dict[str, Callable[[dict[str, Any]], None]] = {
    "file scheme": _set(["request", "url"], "file:///etc/passwd"),
    "gopher scheme": _set(["request", "url"], "gopher://example.com/"),
    "userinfo in url": _set(["request", "url"], "http://user:pw@example.com/x"),
    "fragment in url": _set(["request", "url"], "https://example.com/x#frag"),
    "no host": _set(["request", "url"], "http:///path"),
    "env ref in url": _set(["request", "url"], "https://example.com/${TOKEN}"),
    "method GET": _set(["request", "method"], "GET"),
    "method DELETE": _set(["request", "method"], "DELETE"),
    "two placeholders": _set(["request", "body"], {"a": "{{payload}}", "b": ["{{payload}}"]}),
    "placeholder inside larger string": _set(["request", "body"], {"a": "prefix {{payload}}"}),
    "padded placeholder leaf": _set(["request", "body"], {"a": "{{ payload }}"}),
    "no placeholder": _set(["request", "body"], {"a": "hello"}),
    "placeholder in key": _set(["request", "body"], {"{{payload}}": "x"}),
    "body not an object": _set(["request", "body"], ["{{payload}}"]),
    "retries too high": _set(["limits", "retries"], 99),
    "negative retries": _set(["limits", "retries"], -1),
    "concurrency zero": _set(["limits", "concurrency"], 0),
    "concurrency too high": _set(["limits", "concurrency"], 33),
    "rps too low": _set(["limits", "requests_per_second"], 0),
    "rps too high": _set(["limits", "requests_per_second"], 51),
    "timeout too high": _set(["limits", "timeout_seconds"], 121),
    "max_requests zero": _set(["limits", "max_requests"], 0),
    "max_requests too high": _set(["limits", "max_requests"], 5001),
    "max_attempts zero": _set(["limits", "max_attempts"], 0),
    "max_attempts too high": _set(["limits", "max_attempts"], 30001),
    "max_attempts below max_requests": _set(["limits", "max_attempts"], 100),
    "max_bytes too high": _set(["response", "max_bytes"], 5 * 1024 * 1024 + 1),
    "authorization not confirmed": _set(["authorization", "confirmed"], False),
    "authorization missing": _delete(["authorization"]),
    "scope_note missing": _delete(["authorization", "scope_note"]),
    "scope_note too long": _set(["authorization", "scope_note"], "x" * 201),
    "header value CRLF": _set(["request", "headers", "X-Test"], "a\r\nInjected: 1"),
    "header name with space": _set(["request", "headers", "Bad Name"], "v"),
    "literal Authorization": _set(["request", "headers", "Authorization"], "Bearer abc"),
    "literal x-api-key lowercase": _set(["request", "headers", "x-api-key"], "abc"),
    "literal Cookie": _set(["request", "headers", "Cookie"], "sid=abc"),
    "fragment too short": _set(["secret_fragments"], [{"id": "a", "value": "short"}]),
    "duplicate fragment ids": _set(
        ["secret_fragments"],
        [{"id": "a", "value": "123456"}, {"id": "a", "value": "654321"}],
    ),
    "fragment both value and env": _set(
        ["secret_fragments"], [{"id": "a", "value": "123456", "value_env": "X"}]
    ),
    "fragment neither value nor env": _set(["secret_fragments"], [{"id": "a"}]),
    "unknown top-level key": _set(["surprise"], 1),
    "unknown nested key": _set(["limits", "surprise"], 1),
    "bad network policy": _set(["network", "policy"], "anything"),
    "too many redirects": _set(["network", "max_redirects"], 11),
    "path with brackets": _set(["response", "path"], "a[0]"),
    "path with expression": _set(["response", "path"], "$..x"),
    "empty path": _set(["response", "path"], ""),
    "path too long": _set(["response", "path"], "a" * 201),
    "unsupported version": _set(["version"], 2),
}


def test_valid_config_parses() -> None:
    config = parse_config(copy.deepcopy(VALID))
    assert isinstance(config, TargetConfig)
    assert config.request.method == "POST"
    assert config.limits.concurrency == 4


def test_negative_suite_has_at_least_twenty_cases() -> None:
    assert len(NEGATIVE_CASES) >= 20


@pytest.mark.parametrize("name", sorted(NEGATIVE_CASES))
def test_invalid_config_is_rejected(name: str) -> None:
    data = mutated(NEGATIVE_CASES[name])
    with pytest.raises(ConfigError):
        parse_config(data)


def test_config_is_immutable() -> None:
    config = parse_config(copy.deepcopy(VALID))
    with pytest.raises(ValidationError):
        config.__setattr__("name", "other")


def test_non_mapping_top_level_is_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config(["not", "a", "mapping"])


def test_error_message_does_not_echo_input_values() -> None:
    data = mutated(_set(["request", "headers", "Authorization"], "Bearer topsecretvalue"))
    with pytest.raises(ConfigError) as info:
        parse_config(data)
    assert "topsecretvalue" not in str(info.value)


MORE_NEGATIVE_CASES: dict[str, Callable[[dict[str, Any]], None]] = {
    "literal secret next to env ref": _set(
        ["request", "headers", "Authorization"], "Bearer sk-LIVE-123456 ${X}"
    ),
    "unlisted credential header X-Auth-Token": _set(
        ["request", "headers", "X-Auth-Token"], "sk-LIVE-999"
    ),
    "x-goog-api-key literal": _set(["request", "headers", "x-goog-api-key"], "abc"),
    "url with newline": _set(["request", "url"], "http://exa\nmple.com/x"),
    "url with space": _set(["request", "url"], "https://example.com/a b"),
    "url non-ascii": _set(["request", "url"], "https://exämple.com/x"),
    "url invalid port": _set(["request", "url"], "http://example.com:99999/x"),
    "api_key in query": _set(["request", "url"], "https://example.com/x?api_key=abc"),
    "token in query": _set(["request", "url"], "https://example.com/x?Token=abc&a=1"),
}


@pytest.mark.parametrize("name", sorted(MORE_NEGATIVE_CASES))
def test_hardened_invalid_config_is_rejected(name: str) -> None:
    with pytest.raises(ConfigError):
        parse_config(mutated(MORE_NEGATIVE_CASES[name]))


def test_env_ref_with_scheme_prefix_and_cookie_style_are_accepted() -> None:
    data = mutated(_set(["request", "headers", "Cookie"], "sid=${SESSION_ID}"))
    assert parse_config(data)
    assert parse_config(mutated(_set(["request", "headers", "X-Api-Key"], "${KEY}")))


def test_config_error_does_not_chain_the_raw_input() -> None:
    data = mutated(_set(["request", "headers", "Authorization"], "Bearer sk-LIVE-123456"))
    with pytest.raises(ConfigError) as info:
        parse_config(data)
    assert info.value.__cause__ is None
    assert info.value.__suppress_context__


def test_max_attempts_defaults_to_a_moderate_budget_above_the_default_request_cap() -> None:
    from injectkit.config import DEFAULT_MAX_ATTEMPTS, Limits

    limits = Limits()
    assert limits.max_attempts == DEFAULT_MAX_ATTEMPTS == 1000
    assert limits.max_attempts >= limits.max_requests


def test_max_attempts_equal_to_max_requests_is_accepted() -> None:
    from injectkit.config import Limits

    assert Limits(max_requests=300, max_attempts=300).max_attempts == 300
