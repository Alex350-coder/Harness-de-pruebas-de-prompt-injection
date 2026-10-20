import io
import re
from collections.abc import Callable
from typing import Literal

import pytest
from rich.console import Console

from injectkit.models import Outcome, RunResult
from injectkit.redact import Redactor
from injectkit.report.console import render_console

RunFactory = Callable[..., RunResult]
FRAGMENT = "sk-live-ALPHA-9f3b"
COLOR_CODE = re.compile(r"\x1b\[[0-9;]*(3\d|4\d|9\d)[;m]")


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)


def render(
    run: RunResult,
    redactor: Redactor | None = None,
    *,
    terminal: bool = False,
    color_system: Literal["standard"] | None = None,
) -> str:
    buffer = io.StringIO()
    console = Console(
        file=buffer,
        force_terminal=terminal,
        color_system=color_system,
        width=100,
        legacy_windows=False,
    )
    render_console(
        run, console, redactor=redactor or Redactor(), target_url="http://u:p@x.test/c?k=1"
    )
    return buffer.getvalue()


def test_summary_lists_every_outcome_with_counts(make_run: RunFactory) -> None:
    output = render(make_run())
    for outcome in Outcome:
        assert outcome.value in output
    assert "Findings (2)" in output
    assert "Errors (1)" in output


def test_findings_show_detector_evidence_and_limitation(make_run: RunFactory) -> None:
    output = render(make_run())
    assert "p-1 / canary" in output
    assert "INJK-0123456789abcdef" in output
    assert "limitation: Shows instruction-following" in output
    assert "[HIGH]" in output


def test_footer_states_no_indicator_is_not_secure(make_run: RunFactory) -> None:
    assert "No indicator ≠ secure" in render(make_run())


def test_markup_and_ansi_in_untrusted_text_are_rendered_literally(make_run: RunFactory) -> None:
    hostile = "[bold red]pwn[/bold red] \x1b[31mred\x1b[0m \x1b]0;title\x07 end"
    output = render(make_run(evidence=hostile, error_message=hostile))
    assert "[bold red]pwn[/bold red]" in output
    assert "\x1b" not in output
    assert "\x07" not in output
    assert "red" in output
    assert "end" in output


def test_ansi_never_reaches_a_color_terminal_from_untrusted_text(make_run: RunFactory) -> None:
    output = render(
        make_run(evidence="\x1b[31mDANGER\x1b[0m"), terminal=True, color_system="standard"
    )
    assert "\x1b[31mDANGER" not in output
    assert "DANGER" in output


def test_secrets_are_masked_everywhere(make_run: RunFactory) -> None:
    redactor = Redactor()
    redactor.add(FRAGMENT, label="frag")
    output = render(
        make_run(evidence=f"a {FRAGMENT} b", error_message=f"boom {FRAGMENT}"), redactor
    )
    assert FRAGMENT not in output
    assert "[REDACTED:frag]" in output


def test_secret_split_by_a_control_character_is_still_masked(make_run: RunFactory) -> None:
    redactor = Redactor()
    redactor.add(FRAGMENT, label="frag")
    split = FRAGMENT[:5] + "\x1b[0m" + FRAGMENT[5:]
    output = render(make_run(evidence=split), redactor)
    assert FRAGMENT not in output


def test_url_credentials_and_query_are_not_printed(make_run: RunFactory) -> None:
    output = render(make_run())
    assert "http://x.test/c" in output
    assert "u:p" not in output
    assert "k=1" not in output


def test_no_color_environment_disables_color(
    make_run: RunFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True, color_system="standard", width=100)
    render_console(make_run(), console, redactor=Redactor())
    assert COLOR_CODE.search(buffer.getvalue()) is None


def test_non_tty_output_has_no_escape_sequences(make_run: RunFactory) -> None:
    buffer = io.StringIO()
    console = Console(file=buffer, width=100)
    render_console(make_run(), console, redactor=Redactor())
    assert "\x1b" not in buffer.getvalue()


def test_ascii_fallback_when_the_stream_cannot_encode_the_sign(make_run: RunFactory) -> None:
    class Narrow(io.StringIO):
        encoding = "cp437"

    stream = Narrow()
    console = Console(file=stream, width=100)
    render_console(make_run(), console, redactor=Redactor())
    assert "No indicator != secure" in stream.getvalue()


def test_interrupted_run_is_flagged(make_run: RunFactory) -> None:
    run = make_run().model_copy(update={"interrupted": True})
    assert "interrupted" in render(run)


def test_run_without_findings_says_it_proves_nothing(make_run: RunFactory) -> None:
    run = make_run(outcomes=(Outcome.NO_INDICATOR,))
    output = render(run)
    assert "Findings (0)" in output
    assert "does not prove the target is secure" in output
    assert "Errors" not in output


def test_text_the_stream_cannot_encode_is_escaped_instead_of_crashing(
    make_run: RunFactory,
) -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict", write_through=True)
    console = Console(file=stream, width=100)
    render_console(make_run(evidence="arrow \u2192 and \u65e5\u672c"), console, redactor=Redactor())
    output = raw.getvalue().decode("cp1252")
    assert "\\u2192" in output
    assert "No indicator != secure" in output
