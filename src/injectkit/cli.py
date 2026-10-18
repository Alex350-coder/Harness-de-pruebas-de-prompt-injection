"""Command-line interface. Thin: parse args, call the library, map errors to exit codes."""

from __future__ import annotations

import asyncio
import traceback
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer

from injectkit import __version__
from injectkit.check import probe, safe_excerpt
from injectkit.config import load_config
from injectkit.errors import InjectKitError, TargetError
from injectkit.models import ErrorKind
from injectkit.redact import strip_control

EXIT_USAGE = 2
EXIT_EXECUTION = 3

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Authorized prompt-injection testing for LLM-powered HTTP apps.",
)


class _State:
    debug = False


@app.callback()
def main(
    debug: Annotated[
        bool, typer.Option("--debug", help="Show a (redacted) traceback on errors.")
    ] = False,
) -> None:
    _State.debug = debug


def _fail(exc: BaseException) -> typer.Exit:
    message = strip_control(f"error: {exc}").splitlines()[0]
    typer.echo(message, err=True)
    if _State.debug:
        trace = "".join(traceback.format_exception(exc, chain=False))
        typer.echo(strip_control(trace), err=True)
    return typer.Exit(EXIT_USAGE)


@app.command()
def version() -> None:
    """Print the InjectKit version."""
    typer.echo(f"injectkit {__version__}")


@app.command()
def validate(
    config_path: Annotated[Path, typer.Argument(help="Path to the target YAML config.")],
) -> None:
    """Validate a target config and print a redacted summary."""
    try:
        resolved = load_config(config_path)
    except InjectKitError as exc:
        raise _fail(exc) from exc
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
    try:
        resolved = load_config(config_path)
    except InjectKitError as exc:
        raise _fail(exc) from exc
    mode = resolved.config.network.policy
    if mode != "public_only":
        typer.echo(
            f"warning: network policy '{mode}' allows non-public addresses; "
            "use it only for systems you own.",
            err=True,
        )
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
