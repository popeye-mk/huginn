"""Tests for the scheduled patrol's event triage.

This is the rule that decides what wakes the operator at 3am, so it is
pinned hard. Every test here exists because the logic got it wrong first:

  - Routine `info` churn was reported as an incident. A pass patrol itself
    called quiet produced eleven `lan_gone_*` lines (phones sleeping) and
    the wrapper announced "11 change events". On a real LAN that fires every
    hour, which is how an operator learns to ignore the one line that matters.
  - A crashed classifier printed "quiet". Silence from a broken tool read
    exactly like silence from a clean network — the failure this project
    exists to refuse, committed by the code meant to catch it.

Run: python3 tools/test_patrol_summary.py
"""

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.timeline import triage_events  # noqa: E402
from tools.patrol_summary import main, render  # noqa: E402


def run_cli(payload):
    """Drive the CLI exactly as the wrapper does — stdin in, text + code out.

    Deliberately NOT subprocess: `test_subprocess_only_in_engines` keeps
    shelling out inside engines/, and a test file is not a CI harness. Calling
    main() with stdin redirected exercises the same path (stdin -> triage ->
    render -> stdout -> exit code) without spawning anything.
    """
    stdin, buffer = sys.stdin, io.StringIO()
    sys.stdin = io.StringIO(payload)
    try:
        with redirect_stdout(buffer):
            code = main([])
    finally:
        sys.stdin = stdin
    return code, buffer.getvalue()

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def line(severity, message="x", event_id="e"):
    return json.dumps({"ts": "2026-07-27T13:00:00+02:00", "machine": "m",
                       "id": event_id, "severity": severity, "message": message})


# --- the split that matters ------------------------------------------------

def test_info_churn_is_routine_not_an_incident():
    """Eleven phones leaving is not eleven incidents."""
    t = triage_events([line("info", "Device no longer seen: aa:bb")] * 11)
    check(t.routine == 11, "all eleven counted as routine")
    check(t.notable == [], "none of them is notable")
    check(t.should_report is False, "routine churn does not wake anyone")


def test_anything_above_info_is_notable():
    t = triage_events([line("warning", "new device"), line("critical", "arp spoof"),
                       line("info", "device gone")])
    check(len(t.notable) == 2, "warning and critical are both notable")
    check(t.routine == 1, "the info line stays routine")
    check(t.should_report is True, "a notable finding is reported")


def test_an_unknown_severity_is_surfaced_not_filed_as_normal():
    """A severity nobody has taught this code about must fail LOUD.

    The tempting default is the opposite — treat unrecognised as harmless —
    and it is wrong: a new severity added upstream would go unnoticed
    precisely because it was new.
    """
    t = triage_events([line("catastrophic", "something new")])
    check(len(t.notable) == 1, "an unrecognised severity is surfaced")
    check(t.routine == 0, "and is never counted as routine")


def test_severity_matching_ignores_case_and_padding():
    t = triage_events([line("INFO"), line(" Info ")])
    check(t.routine == 2, "case and whitespace do not change the verdict")


# --- unreadable is never an all-clear --------------------------------------

def test_a_malformed_line_is_counted_never_dropped():
    t = triage_events(["{not json", line("info")])
    check(t.unreadable == 1, "the bad line is counted")
    check(t.routine == 1, "the good line still classifies")
    check(t.should_report is True,
          "a line we could not read is NOT a line we can call harmless")


def test_json_that_is_not_an_object_is_unreadable():
    t = triage_events(["[1,2,3]", '"a string"'])
    check(t.unreadable == 2, "valid JSON of the wrong shape is still unreadable")


def test_blank_lines_are_ignored_entirely():
    t = triage_events(["", "   ", "\n"])
    check((t.notable, t.routine, t.unreadable) == ([], 0, 0),
          "blank lines are noise, not events")


def test_nothing_at_all_is_quiet():
    t = triage_events([])
    check(t.should_report is False, "no events means nothing to report")


# --- the wrapper's parsing contract ----------------------------------------

def test_render_emits_the_three_counts_the_wrapper_reads():
    out = render(triage_events([line("critical", "arp spoof"), line("info"),
                                "{bad"])).splitlines()
    check(out[0] == "1" and out[1] == "1" and out[2] == "1",
          "lines 1-3 are notable/routine/unreadable, in that order")
    check(out[3].startswith("    [critical]") and "arp spoof" in out[3],
          "detail lines are indented and carry severity + message")


def test_render_caps_detail_and_says_how_many_it_hid():
    out = render(triage_events([line("warning", "w")] * 15), max_detail=3).splitlines()
    check(out[0] == "15", "the count is complete even when the detail is capped")
    check(len([x for x in out if x.startswith("    [")]) == 3, "only 3 spelled out")
    check("and 12 more" in out[-1], "the hidden remainder is stated, not dropped")


# --- the CLI the shell actually invokes ------------------------------------

def test_the_cli_round_trips_through_stdin():
    """The wrapper pipes journal lines in; this is that exact path."""
    code, out = run_cli("\n".join([line("critical", "gateway MAC changed"),
                                   line("info")]))
    check(code == 0, "classifying successfully exits 0")
    lines = out.splitlines()
    check(lines[0] == "1" and lines[1] == "1" and lines[2] == "0",
          "counts survive the pipe")
    check("gateway MAC changed" in out, "the message reaches the log")


def test_the_cli_exits_zero_on_a_quiet_pass_too():
    """Findings are not failures: a clean pass and a busy pass both exit 0.

    The wrapper distinguishes 'the guard is down' (non-zero) from 'the guard
    found something' (zero, reported in the text) — a red unit must mean the
    guard stopped working, never that it worked and saw an attack.
    """
    code, out = run_cli("")
    check(code == 0, "an empty pass is still a successful run")
    check(out.splitlines()[:3] == ["0", "0", "0"], "three zeroes")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
