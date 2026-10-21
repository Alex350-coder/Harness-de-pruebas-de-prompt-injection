"""Rich console report. Untrusted text is masked, control-stripped and never parsed as markup."""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Console
from rich.table import Table
from rich.text import Text

from injectkit.models import Finding, Outcome, RunResult, Severity, TestResult
from injectkit.redact import Redactor, strip_control
from injectkit.report import sanitize_url

OUTCOME_ORDER = (
    Outcome.CONFIRMED,
    Outcome.POTENTIAL,
    Outcome.INCONCLUSIVE,
    Outcome.NO_INDICATOR,
    Outcome.ERROR,
)
OUTCOME_STYLE = {
    Outcome.CONFIRMED: "bold red",
    Outcome.POTENTIAL: "yellow",
    Outcome.INCONCLUSIVE: "cyan",
    Outcome.NO_INDICATOR: "green",
    Outcome.ERROR: "magenta",
}
SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
FOOTER_DETAIL = (
    "a run with no indicator only means the configured detectors saw nothing; "
    "it is not evidence that the target is safe."
)


@dataclass(frozen=True, slots=True)
class _Safe:
    """Turns untrusted strings into plain ``Text`` that the output stream can encode."""

    redactor: Redactor
    encoding: str

    def __call__(self, value: str) -> Text:
        cleaned = strip_control(self.redactor.mask(strip_control(value)))
        # Characters the stream cannot encode (for example "→" on a cp1252 pipe) would raise
        # UnicodeEncodeError while printing; show them as \uXXXX escapes instead.
        printable = cleaned.encode(self.encoding, "backslashreplace").decode(self.encoding)
        return Text(printable)


def _footer(console: Console) -> str:
    try:
        "≠".encode(console.encoding)
    except UnicodeEncodeError:
        return f"No indicator != secure: {FOOTER_DETAIL}"
    return f"No indicator ≠ secure: {FOOTER_DETAIL}"


def _label(name: str, value: str, safe: _Safe) -> Text:
    line = Text(f"    {name}: ", style="dim")
    line.append_text(safe(value))
    return line


def _findings_sorted(run: RunResult) -> list[Finding]:
    findings = [f for result in run.results for f in result.findings]
    rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (f.outcome is not Outcome.CONFIRMED, rank[f.severity]))
    return findings


def _summary_table(run: RunResult) -> Table:
    table = Table(title="Results by outcome", title_justify="left")
    table.add_column("Outcome")
    table.add_column("Tests", justify="right")
    for outcome in OUTCOME_ORDER:
        count = run.counts.get(outcome.value, 0)
        table.add_row(Text(outcome.value, style=OUTCOME_STYLE[outcome]), str(count))
    return table


def _print_findings(console: Console, run: RunResult, safe: _Safe) -> None:
    findings = _findings_sorted(run)
    console.print(Text(f"\nFindings ({len(findings)})", style="bold"))
    if not findings:
        console.print(Text("  none (this does not prove the target is secure)"))
        return
    for finding in findings:
        head = Text("  ")
        head.append(f"[{finding.severity.value.upper()}]", style=OUTCOME_STYLE[finding.outcome])
        head.append(f" {finding.outcome.value} ")
        head.append_text(safe(f"{finding.payload_id} / {finding.detector}"))
        head.append(f" (confidence: {finding.confidence.value})")
        console.print(head)
        console.print(_label("indicator", finding.matched_indicator, safe))
        console.print(_label("evidence", finding.evidence, safe))
        console.print(_label("limitation", finding.limitations, safe))
        console.print(_label("fix", finding.remediation, safe))


def _print_errors(console: Console, errors: list[TestResult], safe: _Safe) -> None:
    console.print(Text(f"\nErrors ({len(errors)})", style="bold"))
    for result in errors:
        if result.error is None:
            continue
        line = Text("  ")
        line.append_text(safe(result.payload_id))
        line.append(f": {result.error.kind.value}: ")
        line.append_text(safe(result.error.message))
        console.print(line)


def render_console(
    run: RunResult,
    console: Console,
    *,
    redactor: Redactor,
    target_url: str | None = None,
) -> None:
    """Print the run summary, findings, errors and the mandatory "not proof of safety" footer."""
    safe = _Safe(redactor, console.encoding)
    console.print(Text("InjectKit report", style="bold"))
    console.print(_label("target", run.target_id, safe))
    if target_url is not None:
        console.print(_label("url", sanitize_url(target_url), safe))
    console.print(_label("suite", run.suite, safe))
    console.print(_label("run id", run.run_id, safe))
    console.print(_summary_table(run))
    if run.interrupted:
        console.print(Text("The run was interrupted; results are partial.", style="bold yellow"))
    _print_findings(console, run, safe)
    errors = [r for r in run.results if r.outcome is Outcome.ERROR]
    if errors:
        _print_errors(console, errors, safe)
    console.print(Text(f"\n{_footer(console)}", style="italic"))
