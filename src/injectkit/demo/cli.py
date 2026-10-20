"""``injectkit-demo`` entry point: loopback bind by default, loud guard for anything else."""

from __future__ import annotations

import ipaddress
import os
import sys
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Annotated

import typer

from injectkit.demo.backends import MODEL_ENV, Backend, OllamaBackend, ScriptedBackend

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
PUBLIC_ENV = "INJECTKIT_DEMO_ALLOW_PUBLIC"
BANNER = """\
!!! WARNING: INTENTIONALLY VULNERABLE DEMO BOUND TO A NON-LOOPBACK ADDRESS !!!
Anyone who can reach this port can talk to a deliberately insecure application.
Use it only on an isolated network you control, and stop it when you are done."""


class BackendName(StrEnum):
    SCRIPTED = "scripted"
    OLLAMA = "ollama"


class BindRefusedError(Exception):
    """A non-loopback bind was requested without both explicit acknowledgements."""


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_bind(host: str, *, allow_public_flag: bool, env: Mapping[str, str]) -> bool:
    """Return True when the bind is public (banner required); raise unless allowed twice."""
    if is_loopback_host(host):
        return False
    if not (allow_public_flag and env.get(PUBLIC_ENV) == "1"):
        raise BindRefusedError(
            f"refusing to bind to non-loopback host '{host}': pass --allow-public-bind "
            f"and set {PUBLIC_ENV}=1 to confirm"
        )
    return True


def make_backend(name: BackendName, env: Mapping[str, str]) -> Backend:
    if name is BackendName.OLLAMA:
        return OllamaBackend(env.get(MODEL_ENV))
    return ScriptedBackend()


def main(argv: Sequence[str] | None = None) -> None:
    try:
        import uvicorn

        from injectkit.demo.app import create_app
    except ImportError:
        sys.stderr.write("the demo needs extra dependencies: pip install 'injectkit[demo]'\n")
        raise SystemExit(2) from None

    cli = typer.Typer(add_completion=False, help="Intentionally vulnerable demo target.")

    @cli.command()
    def serve(
        host: Annotated[
            str, typer.Option(help="Bind address (loopback by default).")
        ] = DEFAULT_HOST,
        port: Annotated[int, typer.Option(min=1, max=65535)] = DEFAULT_PORT,
        backend: Annotated[BackendName, typer.Option(help="Chat backend.")] = BackendName.SCRIPTED,
        allow_public_bind: Annotated[
            bool, typer.Option("--allow-public-bind", help="Needed, with env, for non-loopback.")
        ] = False,
    ) -> None:
        try:
            public = check_bind(host, allow_public_flag=allow_public_bind, env=os.environ)
        except BindRefusedError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(2) from None
        if public:
            typer.echo(BANNER, err=True)
        app = create_app(make_backend(backend, os.environ))
        uvicorn.run(app, host=host, port=port, log_level="warning")

    cli(args=None if argv is None else list(argv), standalone_mode=True)
