"""InjectKit: authorized prompt-injection testing for LLM-powered HTTP apps."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("injectkit")  # single source: `version` in pyproject.toml
except PackageNotFoundError:
    # Running from a bare source tree (no installed metadata): a visible marker, not a guess.
    __version__ = "0+unknown"
