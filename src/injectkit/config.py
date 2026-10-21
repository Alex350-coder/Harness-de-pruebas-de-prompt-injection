"""Target configuration: schema, validation, and environment resolution."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from injectkit.errors import ConfigError
from injectkit.extract import MAX_PATH_CHARS, validate_path
from injectkit.redact import Redactor
from injectkit.yamlio import load_yaml

PLACEHOLDER = "{{payload}}"
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
MIN_FRAGMENT_CHARS = 6
SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "cookie", "proxy-authorization"}
)
# Names containing any of these fragments are treated as credential-bearing too.
SENSITIVE_NAME_HINTS = (
    "key",
    "token",
    "secret",
    "auth",
    "cookie",
    "password",
    "passwd",
    "credential",
)
MIN_SECRET_CHARS = 6

_PLACEHOLDER_RE = re.compile(r"\{\{\s*payload\s*\}\}")
_ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# Credential headers: optional one-word prefix ("Bearer ", "sid=") plus env refs only.
_ENV_ONLY_RE = re.compile(r"(?:[A-Za-z][A-Za-z0-9_-]*[ =])?(?:\$\{[A-Za-z_][A-Za-z0-9_]*\})+")
_URL_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f-\U0010ffff]")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def is_sensitive_name(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_HEADERS or any(hint in lowered for hint in SENSITIVE_NAME_HINTS)


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Authorization(_Model):
    confirmed: bool
    scope_note: Annotated[str, Field(min_length=1, max_length=200)]

    @field_validator("confirmed")
    @classmethod
    def _must_be_true(cls, value: bool) -> bool:
        if not value:
            raise ValueError("authorization.confirmed must be true")
        return value


class RequestConfig(_Model):
    url: str
    method: Literal["POST", "PUT", "PATCH"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any]

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        if "${" in value:
            raise ValueError("environment references are only allowed in header values")
        if _URL_FORBIDDEN_RE.search(value):
            raise ValueError("url must be ASCII without spaces or control characters")
        try:
            parts = urlsplit(value)
            host = parts.hostname
            _ = parts.port  # validates the port range
            query = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError as exc:
            raise ValueError("url is not valid") from exc
        if parts.scheme not in {"http", "https"}:
            raise ValueError("url scheme must be http or https")
        if not host:
            raise ValueError("url must include a host")
        if parts.username is not None or parts.password is not None:
            raise ValueError("url must not contain credentials")
        if parts.fragment or "#" in value:
            raise ValueError("url must not contain a fragment")
        if any(is_sensitive_name(name) for name, _ in query):
            raise ValueError("url query must not carry credentials; use an env-referenced header")
        return value

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, value: dict[str, str]) -> dict[str, str]:
        for name, header_value in value.items():
            if not _HEADER_NAME_RE.fullmatch(name):
                raise ValueError("header names must be valid HTTP tokens")
            if any(c in header_value for c in "\r\n\0") or any(c in name for c in "\r\n\0"):
                raise ValueError("header values must not contain control line characters")
            if is_sensitive_name(name) and not _ENV_ONLY_RE.fullmatch(header_value):
                raise ValueError(
                    f"header '{name}' must consist only of environment references "
                    "(${VAR}) with at most a one-word prefix, not a literal credential"
                )
        return value

    @field_validator("body")
    @classmethod
    def _check_body(cls, value: dict[str, Any]) -> dict[str, Any]:
        leaves = 0
        exact = 0
        stack: list[Any] = [value]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                for key, child in node.items():
                    if _PLACEHOLDER_RE.search(str(key)):
                        raise ValueError("the payload placeholder is not allowed in keys")
                    stack.append(child)
            elif isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, str):
                matches = _PLACEHOLDER_RE.findall(node)
                leaves += len(matches)
                if node == PLACEHOLDER:
                    exact += 1
        if leaves != 1 or exact != 1:
            raise ValueError(
                f"body must contain exactly one string value equal to '{PLACEHOLDER}' "
                "and no other placeholder"
            )
        return value


class ResponseConfig(_Model):
    path: Annotated[str, Field(min_length=1, max_length=MAX_PATH_CHARS)]
    max_bytes: Annotated[int, Field(ge=1, le=MAX_RESPONSE_BYTES)] = 1024 * 1024

    @field_validator("path")
    @classmethod
    def _check_path(cls, value: str) -> str:
        return validate_path(value)


class FragmentSpec(_Model):
    id: Annotated[str, Field(min_length=1, max_length=64)]
    value: str | None = Field(default=None, repr=False)
    value_env: str | None = None

    @model_validator(mode="after")
    def _one_source(self) -> Self:
        if (self.value is None) == (self.value_env is None):
            raise ValueError("fragment needs exactly one of 'value' or 'value_env'")
        if self.value is not None and len(self.value) < MIN_FRAGMENT_CHARS:
            raise ValueError(f"fragment values need at least {MIN_FRAGMENT_CHARS} characters")
        if self.value_env is not None and not _ENV_NAME_RE.fullmatch(self.value_env):
            raise ValueError("value_env must be a valid environment variable name")
        return self


class Limits(_Model):
    timeout_seconds: Annotated[float, Field(gt=0, le=120)] = 30
    concurrency: Annotated[int, Field(ge=1, le=32)] = 4
    requests_per_second: Annotated[float, Field(ge=0.1, le=50)] = 2.0
    retries: Annotated[int, Field(ge=0, le=5)] = 2
    max_requests: Annotated[int, Field(ge=1, le=5000)] = 500


class NetworkConfig(_Model):
    policy: Literal["public_only", "loopback", "private"] = "public_only"
    follow_redirects: bool = False
    max_redirects: Annotated[int, Field(ge=0, le=10)] = 3


class TargetConfig(_Model):
    version: Literal[1]
    authorization: Authorization
    name: Annotated[str, Field(min_length=1, max_length=100)]
    request: RequestConfig
    response: ResponseConfig
    secret_fragments: tuple[FragmentSpec, ...] = ()
    limits: Limits = Field(default_factory=Limits)
    network: NetworkConfig = Field(default_factory=NetworkConfig)

    @model_validator(mode="after")
    def _unique_fragment_ids(self) -> Self:
        ids = [fragment.id for fragment in self.secret_fragments]
        if len(ids) != len(set(ids)):
            raise ValueError("secret_fragments ids must be unique")
        return self


class ResolvedFragment(_Model):
    id: str
    value: str = Field(repr=False)


class ResolvedTarget(BaseModel):
    """A validated config plus resolved secrets. ``redactor`` already knows every secret."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    config: TargetConfig
    headers: dict[str, str] = Field(repr=False)
    fragments: tuple[ResolvedFragment, ...] = Field(repr=False)
    redactor: Redactor = Field(repr=False)


def parse_config(data: object) -> TargetConfig:
    """Validate raw data. Error messages never echo the offending input values."""
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping")
    try:
        return TargetConfig.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or '<root>'}: {err['msg']}"
            for err in exc.errors(include_input=False, include_url=False)
        )
        raise ConfigError(f"invalid config: {problems}") from None


def _lookup(env: Mapping[str, str], name: str) -> str:
    value = env.get(name)
    if not value:
        raise ConfigError(f"environment variable {name} is not set or empty")
    return value


def _lookup_secret(env: Mapping[str, str], name: str) -> str:
    value = _lookup(env, name)
    if len(value) < MIN_SECRET_CHARS:
        raise ConfigError(
            f"environment variable {name} must have at least {MIN_SECRET_CHARS} characters"
        )
    return value


def resolve_config(config: TargetConfig, env: Mapping[str, str]) -> ResolvedTarget:
    """Resolve ``${VAR}`` header references and fragment env values; register secrets."""
    redactor = Redactor()
    headers: dict[str, str] = {}
    for name, template in config.request.headers.items():
        refs = _ENV_REF_RE.findall(template)
        resolved = _ENV_REF_RE.sub(lambda m: _lookup(env, m.group(1)), template)
        for ref in refs:
            redactor.add(_lookup_secret(env, ref))
        if any(c in resolved for c in "\r\n\0"):
            raise ConfigError(f"resolved value of header '{name}' contains control characters")
        headers[name] = resolved
    fragments: list[ResolvedFragment] = []
    for spec in config.secret_fragments:
        value = spec.value if spec.value is not None else _lookup(env, spec.value_env or "")
        if len(value) < MIN_FRAGMENT_CHARS:
            raise ConfigError(
                f"secret fragment '{spec.id}' must have at least {MIN_FRAGMENT_CHARS} characters"
            )
        redactor.add(value, label=spec.id)
        fragments.append(ResolvedFragment(id=spec.id, value=value))
    return ResolvedTarget(
        config=config, headers=headers, fragments=tuple(fragments), redactor=redactor
    )


def load_config(path: Path, env: Mapping[str, str] | None = None) -> ResolvedTarget:
    """Load, validate and resolve a target config file."""
    environment = os.environ if env is None else env
    return resolve_config(parse_config(load_yaml(path)), environment)
