"""Console encoding safety (spec §14.2).

§14.2 bans emoji from terminal output because consoles mangle them. The
codebase then broke its own rule with em-dashes and arrows in KB text
and report copy: on the first real Windows run an em-dash rendered as
"â€"" — UTF-8 bytes shown through cp1252.

These tests cover the general rule rather than that one character:
whatever the terminal can represent gets through untouched, and
whatever it cannot is downgraded to something readable instead of
mangled or fatal.
"""

import io

import pytest

import console
from report import render_text


class Cp437Stream(io.StringIO):
    """A legacy console: the worst realistic case."""
    encoding = "cp437"


class Cp1252Stream(io.StringIO):
    """Default Windows ANSI codepage — the one that produced the bug."""
    encoding = "cp1252"


class Utf8Stream(io.StringIO):
    encoding = "utf-8"


SAMPLE = "Disk failing — back up now → replace the drive… “urgent”"


def test_utf8_stream_keeps_the_original_text():
    """A capable terminal should not be punished for a legacy one."""
    assert console.safe_for_stream(SAMPLE, Utf8Stream()) == SAMPLE


def test_stream_without_declared_encoding_is_left_alone():
    """io.StringIO and captured buffers hold str natively."""
    assert console.safe_for_stream(SAMPLE, io.StringIO()) == SAMPLE


def test_legacy_console_gets_readable_ascii():
    out = console.safe_for_stream(SAMPLE, Cp437Stream())
    assert out.isascii()
    assert "->" in out
    assert "..." in out
    assert '"urgent"' in out


def test_downgraded_output_is_still_meaningful():
    """Transliteration must preserve sense, not just strip characters."""
    out = console.safe_for_stream("back up now → replace", Cp437Stream())
    assert "back up now -> replace" in out


def test_no_output_ever_raises_on_encode():
    """The failure this prevents is a report dying halfway through."""
    for stream_cls in (Cp437Stream, Cp1252Stream, Utf8Stream):
        stream = stream_cls()
        console.write(SAMPLE, stream)
        stream.getvalue().encode(stream.encoding)  # must not raise


def test_unknown_characters_fall_back_rather_than_crash():
    """A character outside the transliteration table still can't kill a run."""
    exotic = "temperature 45℃ 中文"
    out = console.safe_for_stream(exotic, Cp437Stream())
    out.encode("cp437")  # must not raise
    assert out.isascii()


def test_configure_output_never_raises():
    """Called at startup; a detached or exotic stream must not be fatal."""
    console.configure_output()


def test_console_output_is_not_forced_to_utf8():
    """Forcing UTF-8 on a console defeats the transliteration fallback.

    sys.stdout.encoding would then report utf-8, safe_for_stream would
    conclude everything is encodable, and a cp1252 terminal would render
    the resulting bytes as mojibake with nothing to catch it. The first
    attempt at this fix did exactly that.
    """
    class FakeConsole(io.StringIO):
        encoding = "cp1252"
        def isatty(self):
            return True
        def reconfigure(self, **kwargs):
            raise AssertionError("console streams must not be reconfigured")

    assert console.is_console(FakeConsole()) is True
    # A character cp1252 cannot represent still degrades gracefully.
    assert console.safe_for_stream("temp 45\u2103", FakeConsole()).isascii()


def test_full_report_survives_a_legacy_console():
    """End-to-end: the real renderer, the real KB text, a cp437 terminal."""
    import json
    import os
    from interpreter import evaluate, resolve_chains
    from verdict import build_verdict

    path = os.path.join(os.path.dirname(__file__), "fixtures", "dying_disk.json")
    with open(path) as f:
        snapshot = json.load(f)

    findings, worth, not_checked = evaluate(snapshot)
    chains, remaining = resolve_chains(findings)
    text = render_text(snapshot, remaining, worth, not_checked, chains=chains,
                       verdict=build_verdict(findings, not_checked, chains))

    stream = Cp437Stream()
    console.write(text, stream)
    rendered = stream.getvalue()

    rendered.encode("cp437")  # the actual regression: this used to be impossible
    assert "Disk space" in rendered
