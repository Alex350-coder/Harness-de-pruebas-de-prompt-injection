"""Command-line interface. Thin: parse args, call the library, map errors to exit codes."""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer

from injectkit import __version__
from injectkit.config import load_config
from injectkit.errors import InjectKitError
from injectkit.redact import strip_control

EXIT_USAGE = 2

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
