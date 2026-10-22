# Contributing to InjectKit

Thanks for your interest. InjectKit is a small project with a single maintainer, so please keep
changes focused. Start with the [README](README.md) and the [docs](docs/). Release steps are in
[RELEASING.md](RELEASING.md). To report a vulnerability, read [SECURITY.md](SECURITY.md) first.

## Local setup

You need Python 3.12 or newer and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --locked --all-extras
```

Optional tip: if your checkout lives in a synced folder such as OneDrive, keep the virtual
environment outside it by setting `UV_PROJECT_ENVIRONMENT` before running `uv` commands, for
example `export UV_PROJECT_ENVIRONMENT=~/.venvs/injectkit`.

## Quality gates

CI (`.github/workflows/ci.yml`) runs these commands. Run them before you open a pull request:

```bash
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest --cov          # coverage must stay at or above 85%
```

Dependency audit and secret scan (also run by CI and listed in [RELEASING.md](RELEASING.md)):

```bash
uv export --locked --all-extras --no-emit-project -o req.txt
uv run pip-audit -r req.txt --disable-pip --require-hashes
gitleaks detect --source . --no-banner --redact
```

`gitleaks` is a separate tool that you install yourself. Do not commit `req.txt`.

## Project rules

- No mocks or fake implementations in `src/`. Mocks and fixtures belong in `tests/`.
- No hardcoded credentials. Config uses `${ENV_VAR}` references and dummy names in examples.
- No bare `except` and no swallowed errors; handle or re-raise with a typed error.
- No unsafe parsing or execution: no `eval`, `exec` or `pickle`, only safe YAML loading, and Jinja2
  only through the project sandbox.
- No `# noqa`, `# type: ignore`, `skip` or `xfail` without a written reason. Never lower a quality
  threshold to make a check pass.
- Every new behavior ships with tests in the same change, including at least one negative case.
- Keep dependencies minimal. A new dependency needs a one-line justification in the pull request.
- Payloads must be benign (see below). Do not add defaults or examples that point at systems you
  do not own. See [docs/authorization.md](docs/authorization.md).

## Payload review checklist

Read [docs/payloads.md](docs/payloads.md) for the full checklist. In short, every payload must have:

- a benign objective (canary emission or disclosure of a value you configured);
- a detectable canary or fragment;
- no real-harm content (no malware, exploit code, personal data, real people or credentials);
- `reviewed: true` set only after the review, with the reviewer recorded in the file header;
- a human review. AI-assisted payloads still need a person to read and approve them.

## Adding a payload

1. Add it to the matching category file under `src/injectkit/payloads/data/suites/library/`, with
   a unique `id`, a `category` from [docs/payloads.md](docs/payloads.md) and a concrete remediation.
2. Apply the review checklist, then set `reviewed: true`.
3. Run `uv run pytest tests/unit/test_library.py tests/unit/test_suites.py`. These tests enforce
   the mechanical parts of the checklist. Add a test if your payload needs new behavior.

## Adding a detector

1. Implement the `Detector` protocol in `src/injectkit/detectors.py` and register it in
   `build_detectors`. See [docs/detectors.md](docs/detectors.md).
2. Add a test file under `tests/unit/` with a positive case, a negative case and a
   known-limitation case. Detectors must never report success because of an HTTP 200 or
   compliant-sounding text.
3. Document false negatives in [docs/detectors.md](docs/detectors.md).

## Commit messages

Use conventional commits, as in the existing history: `feat: ...`, `fix: ...`, `docs: ...`,
`ci: ...`, `build: ...`, `chore: ...`. Keep the subject short and in the imperative.

## AI-generated changes

Changes written with the help of an AI tool get the same review as any other change. You are
responsible for understanding, testing and verifying what you submit, and for checking that no
invented URLs, contacts or credentials slipped in.
