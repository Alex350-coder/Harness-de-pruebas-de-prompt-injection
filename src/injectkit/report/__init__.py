"""Reports: pure serialization of a ``RunResult`` plus safe output helpers."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from injectkit.errors import ReportError


def sanitize_url(url: str) -> str:
    """Return ``scheme://host[:port]/path`` without userinfo, query or fragment."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port is not None else ""
    return f"{parts.scheme}://{host}{port}{parts.path}"


def check_output_path(path: Path) -> None:
    """Raise `ReportError` early if `path` could not be written atomically."""
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ReportError(f"refusing to overwrite '{path}': not a regular file")
    directory = path.parent if str(path.parent) else Path()
    if not directory.is_dir():
        raise ReportError(f"output directory '{directory}' does not exist")


def write_atomic(path: Path, data: str) -> None:
    """Write ``data`` to ``path`` via a temp file and ``os.replace``.

    Refuses to touch anything that exists and is not a regular file (directories, devices,
    symlinks). The temp file is created with owner-only permissions in the same directory.
    """
    check_output_path(path)
    directory = path.parent
    tmp_name: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".injectkit-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.replace(tmp_name, path)
        tmp_name = None
    except OSError as exc:
        raise ReportError(f"could not write '{path}': {type(exc).__name__}") from None
    finally:
        if tmp_name is not None:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
