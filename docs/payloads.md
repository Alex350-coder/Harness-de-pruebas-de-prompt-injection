# Built-in payload library

InjectKit ships a small, reviewed library of prompt-injection test payloads. They are meant for
**authorized** testing of LLM applications you own or have written permission to test (see
`Planning_files/Rules.md`, rules 13 and 16).

## What a payload is

Each payload is a YAML mapping with: `id`, `category`, `severity`, `title`, `description`,
`template`, optional `checks`, `remediation` and `reviewed: true`.

* **Objective.** Every payload asks for something *benign and detectable*: print a per-test canary,
  or restate configured instructions/values. No payload contains instructions for real harm,
  malware, personal data, network addresses or encoded blobs.
* **Canary.** The runner creates a fresh canary for each send and renders only its two *halves*
  (`{{ canary_a }}`, `{{ canary_b }}`). The full value never appears in the request, so a response
  that contains it shows the model followed the injected instruction; merely echoing the request does
  not match. Templates may output only those two variables (a lint enforces it).
* **Checks.** Optional `contains`, `regex` and `must_contain` rules are heuristics. They only ever
  produce *potential* findings. Regexes are limited to 200 characters, are run on the first 64 KiB of
  a response and are rejected at load time when they contain a nested quantifier such as `(a+)+`.

## Categories (4 payloads each, 32 total)

| Category | Idea |
|---|---|
| `direct_override` | Tell the assistant to ignore or replace its earlier instructions |
| `system_prompt_extraction` | Ask it to repeat, translate or summarize its hidden instructions and configured values |
| `role_play` | Use a persona, mode or story to relax constraints |
| `delimiter_confusion` | Fake end-of-input markers, tags and chat-template tokens |
| `instruction_smuggling` | Hide an instruction in content the assistant is asked to process (plain text only) |
| `canary_exfiltration` | Make the assistant place the canary at a specific, detectable place |
| `output_format_abuse` | Request output shapes that exfiltrate data when auto-rendered (Markdown image/link, HTML comment) |
| `context_stuffing` | Push the instruction far from the start with harmless filler |

## Suites

* `basic` – all 32 payloads.
* `quick` – a representative subset (one payload per category).

Files live in `src/injectkit/payloads/data/suites/` (`basic.yaml`, `quick.yaml`) and
`.../suites/library/<category>.yaml`. A suite can `include` another YAML file from its own directory
and optionally pick payloads with `ids: [...]`.

## Review status

The library was written and reviewed by an AI coding agent (Claude, in a Claude Code session); each file
header records this as `reviewed_by`. **An independent human review has not happened yet.** Do
the review below before relying on the library, and update the headers with your own reviewer
entry.

## Review checklist (apply to every new or changed payload)

1. **Benign objective** – the only goal is canary emission or disclosure of a value *you* configured.
2. **No real-harm content** – no malware, exploit code, weapons, self-harm, illegal-activity or
   personal-data instructions, and no real people, brands or credentials.
3. **No external addresses** – no URLs, hostnames, IPs or e-mail addresses; use relative paths only.
4. **No encodings** – no base64, hex or obfuscated text (plain-text smuggling only).
5. **Canary hygiene** – both halves are present when the payload expects the canary, they are
   separated by text (never `}}{{`), and the rendered request never contains the whole value.
6. **Detectability** – a vulnerable target would leave a deterministic indicator (canary, configured
   fragment) or a clearly documented heuristic check.
7. **Remediation** – a concrete, actionable sentence, not a generic warning.
8. **Severity** – reflects impact if the injection succeeded, not how clever the payload is.
9. **Metadata** – unique `id`, a `category` from the table above, `reviewed: true` set only after the
   steps above, and the reviewer recorded in the file header.

`tests/unit/test_library.py` enforces the mechanical parts of this list (size, uniqueness, categories,
sandbox rendering, canary share, no external references, no encoded blobs, `reviewed` flags, header).
