# Running a suite and reading the report

```text
injectkit run <config.yaml> [--suite basic|quick|PATH.yaml] [--format console|json|sarif]
              [--output FILE] [--fail-on confirmed|potential|never]
              [--max-requests N] [--dry-run] [--include-responses]
```

Only run it against systems you own or are authorized to test (see the `authorization`
block in the config and [authorization.md](authorization.md)).

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

## Limits

* `--dry-run` loads the config and suite, prints the planned request count and limits, and
  sends nothing.
* `--max-requests` can only lower the cap set in the config (`limits.max_requests`); a plan
  above the effective cap is refused before any request is sent.
* `--output` is checked before the run (an existing path must be a regular file, the directory
  must exist, and it must not be the config or suite file) and written atomically (temp file,
  fsync, `os.replace`) after the report has been printed. It receives **SARIF** when
  `--format sarif` is given, and **JSON** otherwise (including the default console format).
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

**SARIF** (`--format sarif`): SARIF 2.1.0 on stdout, and in the `--output` file when that is
also given. It is meant for GitHub Code Scanning. Tests validate the output against the
vendored OASIS 2.1.0 schema (`tests/data/sarif-schema-2.1.0.json`). Uploading to Code Scanning
has not been verified, because the project has no remote repository yet.

* **Results.** Only findings become results. `confirmed` gives `level: "error"`, and `potential`
  gives `level: "warning"`. `no_indicator`, `inconclusive` and `error` produce no result; they
  appear only in the console and JSON reports.
* **Rules.** One rule per payload category that produced a finding, with the id
  `injectkit/<category>`. `properties.security-severity` is the highest severity found in that
  category, mapped as info 1.0, low 3.0, medium 5.0, high 7.5, critical 9.5. `help` holds the
  remediation text of that category's findings.
* **Message.** The outcome, the detector, the matched indicator, the payload id and the
  detector's limitation sentence. The first line of the redacted evidence is added **only with
  `--include-responses`**: alerts in Code Scanning are readable by everyone who can read the
  repository, and the evidence is a slice of the target's reply, which can hold personal data or
  a secret that was never registered with the redactor.
* **Location.** Every result points at the config file, at line 1, column 1. The
  `artifactLocation.uri` is a relative POSIX path from the current directory, percent-encoded.
  Code Scanning resolves it from the repository root, so run InjectKit from there. An absolute
  path is never written; a config outside the current directory is named by its file name only.
  A finding is a runtime observation, not a defect in source code, so the location only says
  which config produced it.
* **Fingerprint.** `partialFingerprints.injectkit/v1` is the first 32 hex digits of a
  SHA-256 over the target name, the payload id and the detector, followed by `:` and an
  occurrence counter. It holds no evidence and no secret, and it is the same across runs of the
  same config and suite. Renaming `name` in the config changes it.
* **Properties.** Each result carries `payload_id`, `detector`, `outcome`, `confidence`,
  `severity`, `target_id` and `remediation`. The run carries `run_id`, `suite` and `target_id`.
  The invocation carries UTC start and end times. `executionSuccessful` is `false` after an
  interrupt, and also when more than half of the tests errored (the same threshold as exit code
  3). Each errored test adds a `toolExecutionNotifications` entry with its payload id, error kind
  and redacted message.
* **Redaction.** Every string goes through the same `Redactor` as the other reports.
* **Line endings.** The stdout copy uses the terminal's line endings (CRLF on Windows). The
  `--output` file always uses LF. Both are valid JSON.

## Outcomes

| Outcome | Meaning |
|---|---|
| `confirmed` | A deterministic indicator: the exact per-test canary, or an exact configured fragment |
| `potential` | A heuristic match (normalized-only match, or a `response_check` rule) |
| `inconclusive` | A reply arrived but was empty; not evidence of safety |
| `no_indicator` | The detectors saw nothing; **not** proof of safety (see [detectors.md](detectors.md)) |
| `error` | Transport or execution failure; no verdict |

HTTP 200 alone never produces a finding.
