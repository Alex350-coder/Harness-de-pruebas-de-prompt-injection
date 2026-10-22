# Target config reference

A target config is a YAML file that describes one HTTP endpoint to test. It is read by
`injectkit validate`, `injectkit check-target` and `injectkit run`, and it is validated by
`injectkit.config.load_config`. The schema is the pydantic model `TargetConfig` in
`src/injectkit/config.py`; this page documents that model, and the tests in
`tests/unit/test_docs_examples.py` check that every complete example below still validates.

Only use a config for a system you own or are permitted to test. Read
[authorization.md](authorization.md) first.

## Loading rules

* The file must be UTF-8 YAML, at most 256 KiB, nested at most 32 levels deep.
* Only the safe YAML loader is used. Anchors and aliases are rejected, and so are duplicate
  mapping keys, with one known gap: a merge key (`<<`) next to a same-named key bypasses the
  duplicate-key check (see [authorization.md](authorization.md#residual-risks)).
* Unknown keys are rejected at every level (`extra="forbid"`). A misspelled key is an error,
  not an ignored setting.
* Every field has a type. Header values must be quoted strings (`X-Count: "5"`, not `5`).
* Error messages name the offending field and environment variable. They never echo a value.
* InjectKit does not read `.env` files. Environment variables come from the process
  environment (`load_config(path)` uses `os.environ` unless an `env` mapping is passed).
* Exit code `2` is used for every config error (see [reporting.md](reporting.md#exit-codes)).

## Complete example

This is `examples/target.example.yaml`. It needs two environment variables:
`CHATBOT_API_KEY` (the bearer token) and `SYSTEM_PROMPT_FRAGMENT` (a configured fragment of the
system prompt that must not appear in replies).

```yaml config
version: 1
authorization:
  confirmed: true
  scope_note: "Own staging chatbot"
name: example-chatbot
request:
  url: https://staging.example.com/api/chat
  method: POST
  headers:
    Authorization: "Bearer ${CHATBOT_API_KEY}"
    Content-Type: application/json
  body:
    messages:
      - role: user
        content: "{{payload}}"
response:
  path: choices.0.message.content
  max_bytes: 1048576
secret_fragments:
  - id: sys-1
    value_env: SYSTEM_PROMPT_FRAGMENT
limits:
  timeout_seconds: 30
  concurrency: 4
  requests_per_second: 2.0
  retries: 2
  max_requests: 500
network:
  policy: public_only
  follow_redirects: false
  max_redirects: 3
```

A minimal config. Every omitted block takes its default (`limits` and `network` defaults are in
the tables below; `secret_fragments` is empty):

```yaml config
version: 1
authorization:
  confirmed: true
  scope_note: "Own staging chatbot"
name: minimal-example
request:
  url: https://staging.example.com/api/chat
  body:
    message: "{{payload}}"
response:
  path: reply
```

A local target that uses the vulnerable demo. The `loopback` policy is needed because the
default `public_only` policy refuses 127.0.0.1. The fragment is a published fake value, see
[demo.md](demo.md):

```yaml config
version: 1
authorization:
  confirmed: true
  scope_note: "Local demo app started by me on loopback"
name: injectkit-demo
request:
  url: http://127.0.0.1:8000/chat
  method: POST
  headers:
    Content-Type: application/json
  body:
    messages:
      - role: user
        content: "{{payload}}"
response:
  path: reply
  max_bytes: 65536
secret_fragments:
  # FAKE value published in this repository; it appears in the demo's system prompt only.
  - id: demo-fragment
    value: "DEMO-FAKE-SECRET-7f3a91"
limits:
  timeout_seconds: 10
  concurrency: 4
  requests_per_second: 10
  retries: 1
  max_requests: 100
network:
  policy: loopback
```

## Top-level fields

| Field | Type | Required | Default | Rules |
|---|---|---|---|---|
| `version` | integer | yes | none | Must be `1`. |
| `authorization` | mapping | yes | none | See [authorization](#authorization). |
| `name` | string | yes | none | 1 to 100 characters. Used as the target id in reports and in SARIF fingerprints. |
| `request` | mapping | yes | none | See [request](#request). |
| `response` | mapping | yes | none | See [response](#response). |
| `secret_fragments` | list | no | `[]` | Each item has a unique `id`. See [secret_fragments](#secret_fragments). |
| `limits` | mapping | no | defaults below | See [limits](#limits). |
| `network` | mapping | no | defaults below | See [network](#network). |

## authorization

| Field | Type | Required | Rules |
|---|---|---|---|
| `confirmed` | boolean | yes | Must be YAML `true`. `false` is rejected with `authorization.confirmed must be true`. |
| `scope_note` | string | yes | 1 to 200 characters. Describe what you are authorized to test. |

`confirmed: true` is an attestation that you are permitted to test the target. InjectKit cannot
verify it, and every config must carry it, including loopback targets.

## request

| Field | Type | Required | Default | Rules |
|---|---|---|---|---|
| `url` | string | yes | none | See URL rules below. |
| `method` | `POST`, `PUT` or `PATCH` | no | `POST` | Any other method is rejected. |
| `headers` | mapping of string to string | no | `{}` | See header rules below. |
| `body` | mapping | yes | none | Must contain the payload placeholder exactly once. See body rules below. |

**URL rules.** The URL must:

* use the `http` or `https` scheme and have a host;
* be ASCII, with no spaces or control characters;
* have a valid port, if one is given;
* carry no user name or password, and no `#` fragment;
* have no query parameter whose name looks like a credential (the same name test as for
  headers, for example `api_key` or `token`). Put credentials in a header instead.

The URL may not contain `${...}`. Environment references are allowed only in header values.

**Header rules.**

* Names must be valid HTTP tokens.
* Values must not contain CR, LF or NUL.
* A header is *credential-bearing* when its name is one of `authorization`, `x-api-key`,
  `api-key`, `cookie` or `proxy-authorization`, or contains `key`, `token`, `secret`, `auth`,
  `cookie`, `password`, `passwd` or `credential` (case-insensitive).
* A credential-bearing header's value must consist only of `${VAR}` references, optionally
  preceded by one word and a space or `=` (for example `Bearer ${TOKEN}` or `sid=${SID}`). A
  literal credential is rejected. The error names the header, not the value.
* If you set no `Content-Type`, `application/json` is sent. If you set no `Accept-Encoding`,
  `identity` is sent, and compressed responses are refused.

**Body rules.** The body is serialized as JSON for each test. The body must contain exactly one
string value that is equal to the placeholder `{{payload}}`, and no other placeholder. The
placeholder must be the whole string: `prefix {{payload}}` and `{{ payload }}` are both
rejected. It may not appear in a key. Other values (numbers, booleans, nested lists and maps) are
sent as written. A `${VAR}` in the body is sent as literal text, not expanded.

Valid and invalid bodies (the invalid ones are shown as text so that they are not validated as
configs):

```text
valid:    body: {messages: [{role: user, content: "{{payload}}"}]}
invalid:  body: {message: "Question: {{payload}}"}          # not a whole value
invalid:  body: {message: "{{payload}}", other: "{{payload}}"}  # two placeholders
invalid:  body: {message: "hello"}                          # no placeholder
```

## response

| Field | Type | Required | Default | Rules |
|---|---|---|---|---|
| `path` | string | yes | none | 1 to 200 characters. Dot-separated segments of `A-Z a-z 0-9 _ -`. Numeric segments index lists (`choices.0.message.content`). No wildcards, brackets or expressions. |
| `max_bytes` | integer | no | `1048576` (1 MiB) | 1 to 5242880 (5 MiB). |

The reply must be a JSON document. The value at `path` must be a JSON string, otherwise the test
ends in an `error` outcome with no verdict. The body is read as a stream, and the reply is
refused as soon as it exceeds `max_bytes`; a declared `Content-Length` above the cap is refused
before reading. Non-2xx responses are `error` outcomes, never findings.

## secret_fragments

A list of configured secrets (or any text you do not want a model to repeat). Each item:

| Field | Type | Required | Rules |
|---|---|---|---|
| `id` | string | yes | 1 to 64 characters. Unique within the config. |
| `value` | string | one of `value` / `value_env` | Literal text, at least 6 characters. Prefer `value_env` for real values. |
| `value_env` | string | one of `value` / `value_env` | A valid environment variable name. The variable must be set, non-empty and at least 6 characters. |

Give exactly one of `value` or `value_env`. A fragment that appears in a reply produces a
`secret_fragment` finding. The fragment value is never written to a report: the evidence shows
`[REDACTED:<id>]` instead. Only configured fragments are detected; see
[detectors.md](detectors.md#secret_fragment).

## limits

| Field | Type | Default | Bounds | Meaning |
|---|---|---|---|---|
| `timeout_seconds` | number | `30` | greater than 0, at most 120 | Time limit for one send attempt, including any redirect hops. |
| `concurrency` | integer | `4` | 1 to 32 | Maximum requests in flight. |
| `requests_per_second` | number | `2.0` | 0.1 to 50 | Shared pacing for every attempt, including retries. |
| `retries` | integer | `2` | 0 to 5 | Extra attempts after a timeout, a connection error, or HTTP 429, 502, 503 or 504. |
| `max_requests` | integer | `500` | 1 to 5000 | Cap on planned tests (payloads times runs per payload). Checked before anything is sent. |

Retries wait with exponential backoff: 0.5 s, doubling, capped at 10 s, with jitter between 50%
and 100% of that delay. A `Retry-After` header in seconds form is used instead, capped at 30 s.

`max_requests` counts planned tests only. Retry attempts and redirect hops are not counted
against it. The worst case is therefore planned tests times `retries + 1` attempts, and with
`follow_redirects: true` each attempt may chain up to `max_redirects + 1` requests. See
[authorization.md](authorization.md#rate-and-request-caps).

`injectkit run --max-requests N` can only lower `max_requests`; it never raises it.

## network

| Field | Type | Default | Rules |
|---|---|---|---|
| `policy` | `public_only`, `loopback` or `private` | `public_only` | Address policy, see below. |
| `follow_redirects` | boolean | `false` | When `false`, any 3xx reply is an `error` outcome. |
| `max_redirects` | integer | `3` | 0 to 10. Used only when `follow_redirects` is `true`. |

### Network policy modes

Every address that a host name resolves to must pass the policy. InjectKit resolves host names
itself; an IP literal in the URL is checked directly. The check runs before every attempt and
before every redirect hop.

| Address class | `public_only` (default) | `loopback` | `private` |
|---|---|---|---|
| Globally routable (public) | allowed | allowed | allowed |
| Loopback (`127.0.0.0/8`, `::1`) | denied | allowed | allowed |
| Private (RFC 1918, IPv6 ULA `fc00::/7`) | denied | denied | allowed |
| Link-local, multicast, unspecified, reserved, CGNAT (`100.64.0.0/10`), cloud metadata addresses (`fd00:ec2::254`, `100.100.100.200`), IPv6 tunnel prefixes (`64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`) | always denied | always denied | always denied |
| Any other non-global address | denied | denied | denied |

IPv4-mapped IPv6 addresses are judged by their embedded IPv4 address. A `loopback` or `private`
policy prints a warning on stderr for every run. Use those policies only for systems you own.

Redirects, when `follow_redirects: true`:

* Only 307 and 308 replies are followed. Other 3xx replies are errors.
* Each hop is checked against the network policy, and the target must be http or https.
* An https-to-http downgrade is refused.
* On a cross-origin hop, headers with credential-like names are removed. Other headers are
  forwarded unchanged.

## Environment variable resolution

* Only the form `${NAME}` is recognized, where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`. A bare
  `$NAME` is literal text.
* References are resolved only in header values and in `secret_fragments[].value_env`. They are
  not resolved in `url`, `body` or any other field.
* A referenced variable that is unset or empty is a config error that names the variable.
* Every referenced variable must have at least 6 characters, in any header, not only in
  credential headers.
* The resolved header value must not contain CR, LF or NUL.
* Every resolved value is registered with the redactor, so it is masked in all output (console,
  JSON, SARIF, logs and error messages).

Example, for `TENANT_ID` in a header that is not credential-bearing:

```text
headers:
  X-Tenant: "${TENANT_ID}"    # TENANT_ID must be set and at least 6 characters long
```

## Checking a config

```text
injectkit validate <config.yaml>       # schema and env check; prints a redacted summary
injectkit check-target <config.yaml>   # validate, then send one benign message
injectkit run <config.yaml> --dry-run  # validate, load the suite, print the plan; send nothing
```

Python code can call the same loader:

```python
from pathlib import Path

from injectkit.config import load_config

resolved = load_config(Path("examples/target.example.yaml"))  # reads os.environ
```
