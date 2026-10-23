# Security policy

This policy covers vulnerabilities in InjectKit itself. It does not cover what InjectKit finds in
other systems.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x (pre-release) | Yes |
| anything else | No |

InjectKit is pre-release software. Only the 0.1.x line receives security fixes.

## Reporting a vulnerability

Report vulnerabilities privately by e-mail to **anderaguirre787@gmail.com**. Please do not post
exploit details in a public issue or pull request. If e-mail is not possible, open a public issue
that says only that you have a security report, with no technical details.

## What is in scope

- Secrets leaking through reports, logs, console output or error messages despite redaction.
- SSRF or network-policy bypass (for example reaching private, loopback or link-local addresses
  without the documented acknowledgement, or bypassing redirect or address checks).
- Unsafe parsing or execution: YAML, Jinja2 templates, regular expressions or JSON paths that
  lead to code execution, sandbox escape or unbounded resource use.
- CI and release privilege problems in the workflows of this repository (for example a token with
  more permissions than needed, or secrets reachable from fork pull requests).

## What is out of scope

- Findings that InjectKit produces against third-party or other targets. Report those to the owner
  of that target.
- The designed weaknesses of the intentionally vulnerable demo app. See
  [docs/authorization.md](docs/authorization.md).
- Residual risks already listed in [docs/authorization.md](docs/authorization.md).
- Using InjectKit against systems you do not own or have permission to test.

## What a good report contains

- The InjectKit version and how you installed it, your Python version and operating system.
- A description of the problem and its impact.
- Minimal steps to reproduce, ideally with a small config or payload file that uses dummy values.
- What you expected and what happened.
- Do not include real secrets, real credentials or personal data. Use placeholders.

## Response expectations

This is a small project with a single maintainer working in spare time. No response or fix time is
guaranteed. Reports will be read, and the maintainer will try to acknowledge them, say whether
they are in scope, and fix confirmed issues in the 0.1.x line when practical.

## Safe harbor

Good-faith testing is welcome on your own installation of InjectKit, using your own machine,
accounts and data. This policy does not authorize testing against any system you do not own or
have explicit permission to test, including systems of the maintainer or of other users.

## Related

- [docs/authorization.md](docs/authorization.md): safe-testing policy and residual risks.
- [CONTRIBUTING.md](CONTRIBUTING.md)
