# Safe-testing and authorization policy

InjectKit sends prompt-injection test messages to an HTTP endpoint and reports what it observes.
Those messages are real requests to a real application, so the rules below apply every time you
run it. The tool enforces some of them (marked as enforced); the others are your responsibility.

## Who may be tested

* **Only systems you own, or systems whose owner has given you explicit permission to test.**
  Write the scope down. The config records a short version in `authorization.scope_note`.
* Do not point a config at a third-party production service, a public chatbot, another person's
  account, or a system whose owner has not agreed to the test.
* Prefer a staging or local deployment that you control. Test with fake or non-sensitive data.

**Enforced:** every config must contain `authorization.confirmed: true`. Any other value (or a
missing field) is a config error, exit code 2, and nothing is sent.

**Not enforced:** InjectKit cannot verify ownership or permission. `confirmed: true` is your
written attestation, not a check. The network policy only limits *where* a request can go; it
does not decide whether you may test that place.

## Network policy defaults

* **Enforced:** the default policy is `public_only`. Loopback, private (RFC 1918 and IPv6 ULA),
  link-local, metadata, CGNAT and other non-public addresses are refused. This blocks accidental
  testing of internal networks.
* **Enforced:** `loopback` and `private` are opt-in. They print a warning on stderr on every run
  and on `check-target`. Use them only for systems you run yourself.
* **Enforced:** link-local addresses, cloud metadata addresses and IPv6 tunnel prefixes are always
  denied, in every mode.
* **Enforced:** redirects are off by default. When they are enabled, only 307 and 308 are
  followed, every hop is checked again, and an https-to-http downgrade is refused.

The full table is in [config.md](config.md#network-policy-modes).

## Rate and request caps

| Setting | Default | Hard maximum | Enforced by |
|---|---|---|---|
| `limits.requests_per_second` | 2.0 | 50 | Shared limiter; every attempt, including retries, waits its turn |
| `limits.concurrency` | 4 | 32 | Semaphore on requests in flight |
| `limits.retries` | 2 | 5 | Retries only timeouts, connection errors and HTTP 429, 502, 503, 504 |
| `limits.timeout_seconds` | 30 | 120 | Per send attempt, including redirect hops |
| `limits.max_requests` | 500 | 5000 | Planned tests, checked before any request is sent |
| `response.max_bytes` | 1 MiB | 5 MiB | Declared length and streamed size; compressed replies refused |
| Payloads per suite | — | 200 | Suite loader |
| Suite file size | — | 512 KiB | Suite loader |

`injectkit run --max-requests N` can lower the cap for one run; it can never raise it.

**Important limit of `max_requests`.** The cap is checked against the planned number of tests
(payloads times runs per payload) before the run starts. Retry attempts and redirect hops are not
counted against it. With the defaults and the `basic` suite (32 payloads), the plan is 32 tests,
and each test may send up to 3 attempts, so up to 96 requests. With `follow_redirects: true`
each attempt may also chain up to `max_redirects + 1` requests. Set `retries`,
`requests_per_second` and `max_redirects` with this in mind.

Ctrl+C stops the run, keeps the partial results and exits with code 130.

## Payload content

* Each payload has a benign objective that can be detected: emit a per-test canary, or repeat a
  value that you configured as a secret fragment.
* The library contains no malware, exploit code, weapons, self-harm or illegal-activity
  instructions, no personal data, no real people, brands or credentials, no external addresses
  and no encoded blobs. Mechanical parts of this are checked by `tests/unit/test_library.py`.
  The content review itself is manual.
* **The library was written and reviewed by an AI coding agent only. An independent human review
  is pending.** Review it yourself before relying on it. The checklist is in
  [payloads.md](payloads.md#review-checklist-apply-to-every-new-or-changed-payload).

## The demo is intentionally vulnerable

`injectkit-demo` is a local chat API that is deliberately insecure, so that you can try InjectKit
without a real target. It is not a product and not a model (see [demo.md](demo.md)).

* **Enforced:** it binds to `127.0.0.1` by default. A non-loopback address needs both
  `--allow-public-bind` and the environment variable `INJECTKIT_DEMO_ALLOW_PUBLIC=1`, and it then
  prints a warning banner.
* Do not run it on a shared or public network, do not deploy it, and stop it when you are done.
* Every secret in the demo is fake. The value `DEMO-FAKE-SECRET-7f3a91` is published in this
  repository and is not a credential for anything.

## Secrets and output

* Credentials are read from environment variables, never from the config file. A literal
  credential in a credential-bearing header is rejected (see
  [config.md](config.md#request)).
* Every resolved secret, and every configured fragment, is masked in console, JSON, SARIF, logs
  and error messages. Masking covers the exact value and some encoded forms (base64 and
  percent-encoding variants). It cannot mask a secret that was never configured.
* Reports can contain redacted, truncated excerpts of model replies (`--include-responses`
  adds them to JSON). Treat reports as internal documents.

## Findings are not proof of safety

* A **confirmed** finding means the exact canary, or a configured fragment, appeared in the reply.
  For a canary, that shows the application followed an injected instruction. It is not proof of
  data theft or of exploitability in your setting.
* A **potential** finding is a heuristic match. Review it by hand.
* **no_indicator** and **inconclusive** are not evidence that the target is secure. The detectors
  have documented false negatives (see [detectors.md](detectors.md)).
* An HTTP 200 never produces a finding, and polite or compliant-sounding text never does either.
* A run with exit code 0 is **not** proof that the target is secure.

## Reporting a security issue in InjectKit

TODO-USER: the security reporting contact has not been supplied. Replace this line with the
channel that the maintainer chooses before publishing.

## Residual risks

These are the risks accepted or documented in the project log (`Planning_files/Progress.md`),
summarized here, plus one gap found while writing this page. Nothing below is fixed by this
documentation change.

**Gap found while writing this page (not yet fixed):**

* `limits.max_requests` counts planned tests, not HTTP attempts. Retries and redirect hops are
  outside the cap (see [Rate and request caps](#rate-and-request-caps)). Rule 4 of the project
  rules expects total requests to be capped; this needs a code change and a test, which are
  outside this task.

**Network and HTTP:**

* DNS rebinding: the address is checked when the host is resolved, but the connection is not
  pinned to the checked address. A name could resolve to a different address when the connection
  is made.
* A cancelled DNS lookup keeps an executor thread until the operating-system resolver returns
  (bounded by the OS timeout).
* With `follow_redirects: true`, a cross-origin 307 or 308 hop forwards the JSON body and every
  header that does not look like a credential. Only credential-named headers are stripped.
  Redirects are off by default.

**Parsing and detection:**

* Python's `re` has no timeout. A user-supplied regex with a few unbounded quantifiers can be
  slow on 64 KiB of reply text. The lint that rejects nested quantifiers is a heuristic. Built-in
  payloads contain no regex checks.
* Corpus-documented false negatives (paraphrase, encoding, reversal) and false positives (a
  refusal that quotes the forbidden phrase, broad patterns) are intentional and asserted by tests.
* The normalization is repeated up to four passes. Idempotence was checked exhaustively for short
  inputs over a set of awkward code points, but it is not proven in general.
* YAML: a merge key (`<<`) next to a same-named key bypasses the duplicate-key check. Anchors and
  aliases are blocked, so the impact is limited to strictness. Error messages name fields, not
  values.

**Payload library:**

* Written and reviewed by an AI agent only. Independent human review is pending.

**Demo only:**

* The demo does not validate the `Host` header. A browser on the same machine could, through DNS
  rebinding, reach `/chat`. Only the fake secret is exposed.
* `localhost` is trusted without resolution in the demo's bind guard and in the Ollama URL check.
* The scripted backend is a deliberately vulnerable fixture.

**Files and signals:**

* `write_atomic` replaces the destination with a file created with owner-only permissions. On
  POSIX, an existing file loses its previous mode.
* The Ctrl+C path is tested through the CLI and the runner, but not with a real operating-system
  signal.

**Not yet verified:**

* No remote CI run and no upload to GitHub Code Scanning have been done, because there is no
  remote repository yet.
* The full security review of `src/` (task P5-T06, including `pip-audit`) is still open.
