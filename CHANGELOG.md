# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## [0.1.0] - release candidate (not published)

First release candidate. Nothing has been tagged or published; that is a maintainer action
(see [RELEASING.md](RELEASING.md)).

### Added

- `injectkit` CLI: `version`, `validate`, `check-target` and `run`, with exit codes
  0 (clean), 1 (findings), 2 (usage/config/policy), 3 (execution errors) and 130 (interrupted).
- Validated YAML target config with an explicit authorization acknowledgement, environment-only
  credentials and an SSRF-aware network policy (`public_only` by default).
- Async HTTP target with timeouts, a response size cap, bounded concurrency, a shared rate
  limiter and bounded retries; redirects are off by default and checked per hop.
- Payload suites (`basic`, `quick`) built from a 32-payload library, rendered in a Jinja2
  sandbox with per-test canaries; detectors for canary, secret fragment and response checks.
- Console, JSON (schema-versioned) and SARIF 2.1.0 reports. Every outgoing string is redacted;
  SARIF carries no reply text unless `--include-responses` is given.
- An intentionally vulnerable demo target (`injectkit-demo`, extra `demo`) bound to loopback.
- Documentation (README, config reference, authorization policy, detectors, payloads,
  reporting, demo), `SECURITY.md`, `CONTRIBUTING.md` and `RELEASING.md`.
- CI: quality gate on Python 3.12/3.13, Windows smoke tests, `pip-audit` on the hash-pinned
  lock export (also weekly), `gitleaks` over the full history, wheel build with a clean-venv
  smoke test, and a Code Scanning dogfood job. Dependabot for actions and `uv`.
- A prepared (never triggered) PyPI trusted-publishing workflow.

### Known limitations

See "Residual risks" in [docs/authorization.md](docs/authorization.md). In particular: the
request cap counts planned tests rather than retry attempts, regex checks have no timeout, and
the payload library has not had an independent human review.
