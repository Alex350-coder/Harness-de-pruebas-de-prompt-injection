"""Command-line interface. Thin: parse args, call the library, map errors to exit codes."""

from __future__ import annotations

import asyncio
import contextlib
import traceback
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from rich.console import Console

from injectkit import __version__
from injectkit.check import probe, safe_excerpt
from injectkit.config import ResolvedTarget, load_config
from injectkit.detectors import build_detectors
from injectkit.errors import InjectKitError, ReportError, TargetError
from injectkit.models import ErrorKind, Outcome, RunResult, Suite
from injectkit.payloads.loader import load_suite
from injectkit.redact import Redactor, strip_control
from injectkit.report import check_output_path, sanitize_url, write_atomic
from injectkit.report.console import render_console
from injectkit.report.json_report import to_json
from injectkit.report.sarif import config_uri, to_sarif
from injectkit.runner import RunSettings, check_plan, run_suite
from injectkit.targets.http import HttpTarget

EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_EXECUTION = 3
EXIT_INTERRUPTED = 130
ERROR_RATE_LIMIT = 0.5  # more than half of the tests errored => exit 3

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Authorized prompt-injection testing for LLM-powered HTTP apps.",
)


class OutputFormat(StrEnum):
    CONSOLE = "console"
    JSON = "json"
    SARIF = "sarif"


class FailOn(StrEnum):
    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    NEVER = "never"


class _State:
    debug = False
    redactor: Redactor | None = None


@app.callback()
def main(
    debug: Annotated[
        bool, typer.Option("--debug", help="Show a (redacted) traceback on errors.")
    ] = False,
) -> None:
    _State.debug = debug
    _State.redactor = None


def _clean(text: str) -> str:
    """Control-stripped and, once a config is loaded, secret-masked terminal text."""
    redactor = _State.redactor
    cleaned = strip_control(text)
    return cleaned if redactor is None else strip_control(redactor.mask(cleaned))


def _fail(exc: BaseException, code: int = EXIT_USAGE) -> typer.Exit:
    lines = _clean(f"error: {exc}").splitlines()
    typer.echo(lines[0] if lines else "error", err=True)
    if _State.debug:
        trace = "".join(traceback.format_exception(exc, chain=False))
        typer.echo(_clean(trace), err=True)
    return typer.Exit(code)


def _load(config_path: Path) -> ResolvedTarget:
    """Load a config and register its redactor for every later message."""
    try:
        resolved = load_config(config_path)
    except InjectKitError as exc:
        raise _fail(exc) from exc
    _State.redactor = resolved.redactor
    return resolved


def _warn_policy(resolved: ResolvedTarget) -> None:
    mode = resolved.config.network.policy
    if mode != "public_only":
        typer.echo(
            f"warning: network policy '{mode}' allows non-public addresses; "
            "use it only for systems you own.",
            err=True,
        )


@app.command()
def version() -> None:
    """Print the InjectKit version."""
    typer.echo(f"injectkit {__version__}")


@app.command()
def validate(
    config_path: Annotated[Path, typer.Argument(help="Path to the target YAML config.")],
) -> None:
    """Validate a target config and print a redacted summary."""
    resolved = _load(config_path)
    config = resolved.config
    host = urlsplit(config.request.url).hostname or "?"
    lines = [
        "config OK",
        f"  name:        {config.name}",
        f"  target host: {host}",
        f"  method:      {config.request.method}",
        f"  network:     {config.network.policy}",
        f"  limits:      concurrency={config.limits.concurrency}, "
        f"rps={config.limits.requests_per_second}, retries={config.limits.retries}, "
        f"max_requests={config.limits.max_requests}",
    ]
    typer.echo(strip_control(resolved.redactor.mask("\n".join(lines))))


@app.command("check-target")
def check_target(
    config_path: Annotated[Path, typer.Argument(help="Path to the target YAML config.")],
    show_response: Annotated[
        bool, typer.Option("--show-response", help="Also print a redacted, truncated excerpt.")
    ] = False,
) -> None:
    """Send one benign message to verify connectivity, network policy and extraction."""
    resolved = _load(config_path)
    _warn_policy(resolved)
    try:
        result = asyncio.run(probe(resolved))
    except TargetError as exc:
        message = strip_control(resolved.redactor.mask(f"{exc.kind.value}: {exc}"))
        typer.echo(f"error: {message}", err=True)
        code = EXIT_USAGE if exc.kind is ErrorKind.POLICY else EXIT_EXECUTION
        raise typer.Exit(code) from None
    typer.echo("check OK")
    typer.echo(f"  status: {result.status_code}")
    typer.echo(f"  latency: {result.latency_ms:.0f} ms")
    typer.echo(f"  response length: {len(result.text)} chars")
    if show_response:
        typer.echo(f"  response: {safe_excerpt(resolved, result.text)}")


def exit_code_for(run: RunResult, fail_on: FailOn) -> int:
    """0 clean, 1 findings at/above the threshold, 3 too many errors, 130 interrupted."""
    if run.interrupted:
        return EXIT_INTERRUPTED
    confirmed = run.counts.get(Outcome.CONFIRMED.value, 0)
    potential = run.counts.get(Outcome.POTENTIAL.value, 0)
    if (fail_on is FailOn.CONFIRMED and confirmed) or (
        fail_on is FailOn.POTENTIAL and confirmed + potential
    ):
        return EXIT_FINDINGS
    errors = run.counts.get(Outcome.ERROR.value, 0)
    if run.results and errors / len(run.results) > ERROR_RATE_LIMIT:
        return EXIT_EXECUTION
    return 0


def _load_suite(name_or_path: str) -> Suite:
    is_path = (
        "/" in name_or_path
        or "\\" in name_or_path
        or Path(name_or_path).suffix.lower() in {".yaml", ".yml"}
    )
    return load_suite(Path(name_or_path) if is_path else name_or_path)


def _check_output_target(output: Path, *inputs: Path) -> None:
    """Refuse to write the report over the config or suite file that drives the run."""
    check_output_path(output)
    resolved = output.resolve()
    if any(resolved == path.resolve() for path in inputs):
        raise ReportError("--output must not be the config or suite file")


def _print_plan(
    resolved: ResolvedTarget, suite: Suite, settings: RunSettings, planned: int
) -> None:
    config = resolved.config
    lines = [
        "dry run: nothing was sent",
        f"  target:            {config.name} ({sanitize_url(config.request.url)})",
        f"  network policy:    {config.network.policy}",
        f"  suite:             {suite.name} ({len(suite.payloads)} payloads)",
        f"  runs per payload:  {suite.runs_per_payload}",
        f"  planned requests:  {planned} (cap {settings.max_requests})",
        f"  attempt budget:    {settings.max_attempts} (all sends, retries included)",
        f"  concurrency:       {settings.concurrency}",
        f"  requests/second:   {settings.requests_per_second}",
        f"  retries:           {settings.retries}",
        f"  timeout (s):       {config.limits.timeout_seconds}",
    ]
    typer.echo(_clean("\n".join(lines)))


def _execute(
    resolved: ResolvedTarget, suite: Suite, settings: RunSettings, include_responses: bool
) -> RunResult:
    progress = Console(stderr=True)
    status = (
        progress.status(f"running {len(suite.payloads) * suite.runs_per_payload} requests...")
        if progress.is_terminal
        else contextlib.nullcontext()
    )
    with status:
        return asyncio.run(
            run_suite(
                HttpTarget(resolved),
                suite,
                settings,
                build_detectors(resolved),
                redactor=resolved.redactor,
                target_id=resolved.config.name,
                include_responses=include_responses,
            )
        )


def _emit(
    result: RunResult,
    resolved: ResolvedTarget,
    output_format: OutputFormat,
    output: Path | None,
    include_responses: bool,
    config_path: Path,
) -> None:
    """Print the chosen report first, then write the report file atomically when asked.

    The file holds SARIF when ``--format sarif`` is chosen and JSON otherwise.

    Printing comes first so a failing file write (full disk, locked file) never loses the
    results of a run whose requests were already sent.
    """
    url = resolved.config.request.url
    document = None
    if output_format is OutputFormat.SARIF:
        document = to_sarif(
            result,
            resolved.redactor,
            config_uri=config_uri(config_path),
            include_evidence=include_responses,
        )
    elif output_format is OutputFormat.JSON or output is not None:
        document = to_json(
            result, resolved.redactor, target_url=url, include_responses=include_responses
        )
    if output_format is not OutputFormat.CONSOLE and document is not None:
        typer.echo(document, nl=False)
    else:
        render_console(result, Console(), redactor=resolved.redactor, target_url=url)
    if output is not None and document is not None:
        write_atomic(output, document)
        typer.echo(f"report written to {_clean(str(output))}", err=True)


def _warn_errors(result: RunResult) -> None:
    errors = result.counts.get(Outcome.ERROR.value, 0)
    if errors:
        typer.echo(f"warning: {errors} of {len(result.results)} tests ended in an error", err=True)


@app.command()
def run(
    config_path: Annotated[Path, typer.Argument(help="Path to the target YAML config.")],
    suite: Annotated[
        str, typer.Option("--suite", help="Built-in suite name (basic, quick) or a YAML path.")
    ] = "basic",
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Report printed to stdout (console, json, sarif)."),
    ] = OutputFormat.CONSOLE,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Also write the report (SARIF for sarif, else JSON) here."),
    ] = None,
    fail_on: Annotated[
        FailOn, typer.Option("--fail-on", help="Lowest outcome that makes the exit code 1.")
    ] = FailOn.CONFIRMED,
    max_requests: Annotated[
        int | None,
        typer.Option("--max-requests", min=1, help="Lower the request cap (never raises it)."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the plan and limits; send nothing.")
    ] = False,
    include_responses: Annotated[
        bool,
        typer.Option(
            "--include-responses", help="Add redacted, truncated replies (and SARIF evidence)."
        ),
    ] = False,
) -> None:
    """Run a payload suite against the target and report findings.

    Exit codes: 0 clean; 1 findings at/above --fail-on; 2 usage, config or policy error;
    3 more than half of the tests errored, or the report file could not be written;
    130 interrupted. Precedence: 130, then 1, then 3, so a confirmed finding still exits 1
    when many tests errored (a warning on stderr shows the error count).

    A clean run is not proof of safety.
    """
    resolved = _load(config_path)
    try:
        suite_obj = _load_suite(suite)
        limits = resolved.config.limits
        cap = (
            limits.max_requests if max_requests is None else min(max_requests, limits.max_requests)
        )
        settings = RunSettings.from_limits(limits, max_requests=cap)
        planned = check_plan(suite_obj, settings)
        if output is not None:
            suite_file = Path(suite) if Path(suite).suffix.lower() in {".yaml", ".yml"} else None
            inputs = (config_path,) if suite_file is None else (config_path, suite_file)
            _check_output_target(output, *inputs)
    except InjectKitError as exc:
        raise _fail(exc) from exc
    _warn_policy(resolved)
    if dry_run:
        _print_plan(resolved, suite_obj, settings, planned)
        return
    try:
        result = _execute(resolved, suite_obj, settings, include_responses)
        _emit(result, resolved, output_format, output, include_responses, config_path)
    except ReportError as exc:
        raise _fail(exc, EXIT_EXECUTION) from None
    except InjectKitError as exc:
        raise _fail(exc) from None
    except KeyboardInterrupt:
        typer.echo("interrupted", err=True)
        raise typer.Exit(EXIT_INTERRUPTED) from None
    except Exception as exc:  # last-resort boundary: only the exception type is shown
        raise _fail(RuntimeError(type(exc).__name__), EXIT_EXECUTION) from None
    _warn_errors(result)
    code = exit_code_for(result, fail_on)
    if code:
        raise typer.Exit(code)
