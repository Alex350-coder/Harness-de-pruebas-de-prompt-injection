# InjectKit

InjectKit is a command-line tool for **authorized** prompt-injection testing of LLM-powered
HTTP applications. You describe an endpoint in a YAML file. InjectKit sends a reviewed set of
benign test payloads to it, checks each reply with deterministic detectors, and writes a report
to the console, as JSON, or as SARIF 2.1.0.

> **Authorized use only.** Test only systems you own or have explicit written permission to
> test. A config must carry `authorization.confirmed: true`, which is your attestation and not a
> check. Read [docs/authorization.md](docs/authorization.md) before your first run.

## Status

* Version `0.1.0.dev0`, alpha (`Development Status :: 3 - Alpha`).
* **InjectKit is not published on PyPI.** Install it from a source checkout or from a wheel that
  you build yourself (below).
* Python 3.12 or newer. License: Apache-2.0 (see [LICENSE](LICENSE)).

## What it does and does not do

* Does: send up to 200 payloads per suite (the built-in `basic` suite has 32, in 8 categories),
  each with a fresh canary; detect a canary or a configured secret fragment in the reply;
  refuse private and loopback addresses by default; cap concurrency, rate, retries, reply size
  and planned requests; redact configured secrets from every output.
* Does not: crawl, scan ports, exploit, change the target, or prove that a target is secure.
  "No indicator" means the detectors saw nothing. It does not mean the target is safe. See
  [docs/detectors.md](docs/detectors.md).

## Install

You need Python 3.12 or newer. The examples use a POSIX shell; on Windows, Git Bash works.
If the project folder is inside a synced folder such as OneDrive, set
`UV_PROJECT_ENVIRONMENT` to a path outside it before running `uv` commands, for example
`export UV_PROJECT_ENVIRONMENT=~/.venvs/injectkit`.

### From a source checkout (uv)

```bash
uv sync
uv run injectkit --help
```

### From a built wheel (pip)

Build the wheel and the source distribution with uv (the output goes to `dist/`):

```bash
uv build
```

Then install the wheel into a fresh virtual environment kept outside the project folder. On
Windows (tested with Python 3.12, Git Bash):

```bash
py -3.12 -m venv ~/.venvs/injectkit-wheel
~/.venvs/injectkit-wheel/Scripts/python -m pip install dist/injectkit-0.1.0.dev0-py3-none-any.whl
~/.venvs/injectkit-wheel/Scripts/injectkit version
```

On Linux and macOS, the same steps with `python3.12` and `bin/` instead of `Scripts/` should
work. This has not been tested on those systems.

### One-off run from the wheel (uv, no installation)

```bash
uv run --isolated --no-project --with dist/injectkit-0.1.0.dev0-py3-none-any.whl injectkit version
```

The command is `injectkit version`. There is no `--version` flag.

## Quickstart with the demo

The demo is a local chat API that is **intentionally vulnerable**. It binds to `127.0.0.1` and
uses only fake secrets. Details are in [docs/demo.md](docs/demo.md).

Terminal 1 (from a source checkout):

```bash
uv sync --locked --extra demo
uv run injectkit-demo
```

Terminal 2:

```bash
uv run injectkit validate examples/demo-target.yaml
uv run injectkit run examples/demo-target.yaml --dry-run
uv run injectkit run examples/demo-target.yaml
```

The last command sends 32 requests to the demo and prints a console report. It exits with
code `1` because the demo is designed to be attacked: 28 tests are `confirmed`, and 4 are
`no_indicator`. Stop the demo with Ctrl+C in terminal 1.

`examples/demo-target.yaml` uses `network.policy: loopback`. The default `public_only` policy
refuses `127.0.0.1` on purpose.

## Testing your own endpoint

1. Copy `examples/target.example.yaml` to a file of your own, for example `my-target.yaml`, and
   edit the copy. The example points at a placeholder host (`staging.example.com`) that you
   must not test. Set `url` to a system you own, keep `body` as a whole `{{payload}}` string
   value, set `response.path` to where your reply text lives, and write your own
   `authorization` block. Every field is described in [docs/config.md](docs/config.md).
2. Keep credentials out of the file. Reference them as environment variables. The example
   config reads `CHATBOT_API_KEY` and `SYSTEM_PROMPT_FRAGMENT`:

   ```bash
   export CHATBOT_API_KEY="<your token>"
   export SYSTEM_PROMPT_FRAGMENT="<a fragment of your system prompt>"
   uv run injectkit validate my-target.yaml
   ```

   In PowerShell, use `$env:CHATBOT_API_KEY = "..."`. InjectKit does not read `.env` files.
3. Check the plan with `--dry-run`, which sends nothing. Then run it.

   ```bash
   uv run injectkit run my-target.yaml --dry-run
   uv run injectkit run my-target.yaml
   ```

   `injectkit check-target my-target.yaml` sends one benign message first, to confirm
   connectivity, the network policy and the response path.

## Using `run`

```text
injectkit run <config.yaml> [--suite basic|quick|PATH.yaml] [--format console|json|sarif]
              [--output FILE] [--fail-on confirmed|potential|never]
              [--max-requests N] [--dry-run] [--include-responses]
```

| Option | Meaning |
|---|---|
| `--suite` | `basic` (default, 32 payloads), `quick` (one per category), or a path to a suite YAML file. |
| `--format` | Report printed to stdout: `console` (default), `json`, or `sarif`. |
| `--output FILE` | Also write the report to a file. With `--format sarif` the file gets SARIF; otherwise JSON. The directory must exist. |
| `--fail-on` | Lowest outcome that makes the exit code `1`: `confirmed` (default), `potential`, or `never`. |
| `--max-requests N` | Lower the request cap for this run. It can never raise the cap in the config. |
| `--dry-run` | Print the plan and the limits. Sends nothing. |
| `--include-responses` | Add redacted, truncated replies to the JSON report. |

Write a SARIF report to a file (create the `reports/` directory first; it is git-ignored):

```bash
mkdir -p reports
uv run injectkit run examples/demo-target.yaml --format sarif --output reports/demo.sarif
```

The report formats, the SARIF fields and the outcomes are described in
[docs/reporting.md](docs/reporting.md).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on`, and at most half of the tests errored |
| 1 | At least one finding at or above `--fail-on` (default `confirmed`; `potential` also counts `potential`; `never` disables this) |
| 2 | Usage, config, suite, output-path or policy error, or a plan above the request cap; nothing was sent |
| 3 | The run finished but more than half of the tests errored, the report file could not be written (the report is still printed), or an unexpected internal error |
| 130 | Interrupted (Ctrl+C); partial results are flagged `interrupted` |

Precedence is 130, then 1, then 3: a run with a confirmed finding exits 1 even if many tests
errored (stderr then warns with the error count). Exactly half errored is still exit 0. A clean exit 0 is **not** proof that the target is secure.

## Documentation

* [docs/config.md](docs/config.md): config reference, environment variables and network policy.
* [docs/authorization.md](docs/authorization.md): safe-testing policy, caps and residual risks.
* [docs/reporting.md](docs/reporting.md): `run` options, exit codes, console, JSON and SARIF reports.
* [docs/report-schema.json](docs/report-schema.json): JSON Schema of the JSON report.
* [docs/detectors.md](docs/detectors.md): what each detector guarantees and what it does not.
* [docs/payloads.md](docs/payloads.md): the payload library, suites and the review checklist.
* [docs/demo.md](docs/demo.md): the vulnerable demo target.

## Limitations

* Alpha software (`0.1.0.dev0`). The CLI and the config schema may still change.
* Not published on PyPI. The remote CI workflow and SARIF upload to GitHub Code Scanning are not
  verified yet, because the project has no remote repository.
* Tests only HTTP endpoints that accept a JSON `POST`, `PUT` or `PATCH` and return JSON. Streaming
  replies, WebSockets and multi-turn sessions are not supported.
* Detectors find only what they are built to find: exact canaries and configured fragments, plus
  heuristic rules. Paraphrased or encoded leaks are missed.
* The built-in payload library was reviewed by an AI agent. An independent human review is still
  pending.
* `max_requests` counts planned tests. Retries and redirect hops are not counted. See
  [docs/authorization.md](docs/authorization.md#rate-and-request-caps).

## Development

The quality gate used by this project:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest --cov
```

## License

Apache-2.0. See [LICENSE](LICENSE).
