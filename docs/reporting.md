# Running a suite and reading the report

```text
injectkit run <config.yaml> [--suite basic|quick|PATH.yaml] [--format console|json]
              [--output FILE] [--fail-on confirmed|potential|never]
              [--max-requests N] [--dry-run] [--include-responses]
```

Only run it against systems you own or are authorized to test (see the `authorization`
block in the config).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on`, and at most half of the tests errored |
| 1 | At least one finding at or above `--fail-on` (default `confirmed`; `potential` also counts `potential`; `never` disables this) |
| 2 | Usage, config, suite, output-path or policy error, or a plan above the request cap; nothing was sent |
| 3 | The run finished but more than half of the tests errored (or an unexpected internal error) |
| 130 | Interrupted (Ctrl+C); partial results are flagged `interrupted` |

Findings win over the error rate: a run with a confirmed finding exits 1 even if many
tests errored. A clean exit 0 is **not** proof that the target is secure.

## Limits

* `--dry-run` loads the config and suite, prints the planned request count and limits, and
  sends nothing.
* `--max-requests` can only lower the cap set in the config (`limits.max_requests`); a plan
  above the effective cap is refused before any request is sent.
* `--output` is checked before the run (existing path must be a regular file, directory must
  exist) and written atomically (temp file + `os.replace`). It always receives the JSON report.
* A network policy other than `public_only` prints a warning on stderr.

## Reports

**Console** (default, stdout): a table of tests by outcome, the findings (severity, payload,
detector, matched indicator, redacted evidence, limitation, remediation), an errors section,
and the footer "No indicator != secure". Untrusted text is stripped of ANSI/control
characters, masked and never parsed as Rich markup. `NO_COLOR` and non-tty output carry no
escape codes.

**JSON** (`--format json` or `--output`): `schema_version: "1"`, sorted keys, schema in
[`report-schema.json`](report-schema.json). It never contains request headers or request
bodies; the target URL has its user info and query removed; every string goes through the
`Redactor`. `--include-responses` adds a redacted, control-stripped excerpt of each reply
(at most 2048 characters, with `response_truncated`).

## Outcomes

| Outcome | Meaning |
|---|---|
| `confirmed` | A deterministic indicator: the exact per-test canary, or an exact configured fragment |
| `potential` | A heuristic match (normalized-only match, or a `response_check` rule) |
| `inconclusive` | A reply arrived but was empty; not evidence of safety |
| `no_indicator` | The detectors saw nothing; **not** proof of safety (see [detectors.md](detectors.md)) |
| `error` | Transport or execution failure; no verdict |

HTTP 200 alone never produces a finding.
