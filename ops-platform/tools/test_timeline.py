"""Tests for the guard timeline (G7) — what changed on the LAN over time.

Pins the two disciplines that make the timeline useful instead of noisy:
only real changes are journalled (a standing open port is not news every
3h), and repeats are collapsed at read time (an ongoing anomaly reads as
"since Tuesday, N×", not N identical lines). Plus the honest empty-states:
a never-written journal says the patrol hasn't run; an empty window says so.

Run: python3 tools/test_timeline.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.finding import Coverage, Finding  # noqa: E402
from domains.timeline import append_events, summarize  # noqa: E402
import skills.timeline as timeline_skill  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _f(fid, severity, message, tags):
    return Finding(
        id=fid, source_module="lan-census", machine_id="host",
        severity=severity, confidence="certain", message=message,
        coverage=Coverage(checked=1, total=1), tags=tags,
    )


def _journal():
    return os.path.join(tempfile.mkdtemp(), "census", "guard_events.json")


def _iso(dt):
    return dt.isoformat()


# --- what gets recorded ---------------------------------------------------

def test_standing_open_port_is_not_recorded_but_newly_is():
    j = _journal()
    findings = [
        _f("exp_1", "critical", "192.168.1.5 [tv]: Telnet open", ("exposure", "lan")),
        _f("exp_2", "warning", "192.168.1.6: NEWLY open RDP", ("exposure", "lan")),
    ]
    n = append_events(j, findings, "host")
    check(n == 1, "only the NEWLY-opened port is a change worth recording")
    s = summarize(j, since_days=7)
    check([c.id for c in s.changes] == ["exp_2"], "standing port stayed out")


def test_new_device_and_anomaly_and_vanish_are_recorded():
    j = _journal()
    findings = [
        _f("lan_new_device_aa", "warning", "New device: .46", ("lan", "security")),
        _f("lan_gone_bb", "info", "Device no longer seen: bb", ("lan", "security")),
        _f("arp_1", "warning", "ARP spoof suspected", ("anomaly", "lan")),
    ]
    n = append_events(j, findings, "host")
    check(n == 3, "device in/out and anomaly are all changes")


# --- repeats collapse at read time ---------------------------------------

def test_repeats_collapse_with_count_and_span():
    j = _journal()
    now = datetime(2026, 7, 23, 18, 0, tzinfo=timezone.utc)
    # Same anomaly recorded on three consecutive patrols.
    for h in (0, 3, 6):
        append_events(j, [_f("arp_1", "warning", "ARP spoof suspected",
                             ("anomaly", "lan"))], "host",
                      now=_iso(now - timedelta(hours=6 - h)))
    s = summarize(j, since_days=7, now=_iso(now))
    check(len(s.changes) == 1, "three recordings collapse to one change")
    c = s.changes[0]
    check(c.count == 3, "count reflects how many times it fired")
    check(c.first_ts < c.last_ts, "span runs first→last")
    check(s.total_events == 3, "total events still counts every recording")


# --- windowing ------------------------------------------------------------

def test_window_excludes_older_than_since_days():
    j = _journal()
    now = datetime(2026, 7, 23, tzinfo=timezone.utc)
    append_events(j, [_f("old", "warning", "old change", ("lan",))], "host",
                  now=_iso(now - timedelta(days=30)))
    append_events(j, [_f("new", "warning", "recent change", ("lan",))], "host",
                  now=_iso(now - timedelta(days=2)))
    s = summarize(j, since_days=7, now=_iso(now))
    check([c.id for c in s.changes] == ["new"], "only within-window changes shown")


# --- honest empty-states + the skill -------------------------------------

def test_never_written_journal_is_not_an_all_clear():
    s = summarize(_journal(), since_days=7)
    check(s.has_history is False, "missing journal → no history")
    out = timeline_skill._render(s, "host")
    check("No guard history yet" in out and "not an all-clear" in out.lower(),
          "skill says the patrol hasn't run, not that the LAN is clean")


def test_empty_window_is_reported_plainly():
    j = _journal()
    append_events(j, [_f("x", "warning", "a change", ("lan",))], "host",
                  now=_iso(datetime(2020, 1, 1, tzinfo=timezone.utc)))
    s = summarize(j, since_days=7)                 # nothing within 7 days of now
    check(s.has_history and not s.changes, "history exists but window is empty")
    out = timeline_skill._render(s, "host")
    check("No changes recorded" in out, "empty window is stated plainly")


def test_skill_parses_a_day_count():
    check(timeline_skill._days("timeline 30") == 30, "reads an explicit day count")
    check(timeline_skill._days("timeline") == 7, "defaults to 7")
    check(timeline_skill._days("500") == 365, "clamps to a sane max")


# --- the window must not claim more history than it kept ------------------

def test_a_full_journal_reports_its_window_as_truncated():
    """Chapter two item 4: a quietly shortened window is a quiet lie.

    The journal trims to MAX_JOURNAL_LINES on every write. Ask for 30 days
    on a full journal reaching back 2 and the old answer was a confident
    "N changes in the last 30 days" — about 28 days that had been dropped.
    Reporting a window you cannot see as though you had looked at it is the
    same error as reporting an unchecked host as clean.
    """
    from datetime import timedelta
    from domains.timeline.service import MAX_JOURNAL_LINES

    directory = tempfile.mkdtemp()
    path = os.path.join(directory, "journal.json")
    start = datetime.now(timezone.utc) - timedelta(days=2)
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(MAX_JOURNAL_LINES):
            ts = (start + timedelta(seconds=i * 40)).isoformat()
            fh.write(json.dumps({"ts": ts, "machine": "m", "id": "e",
                                 "severity": "info", "message": "x"}) + "\n")

    summary = summarize(path, since_days=30)
    check(summary.at_capacity, "a full journal knows it is full")
    check(summary.truncated, "and reports the 30-day window as truncated")
    check(summary.oldest_ts, "and names the oldest evidence it still holds")


def test_a_short_journal_never_claims_truncation():
    """The opposite error — crying wolf about history that was never lost."""
    directory = tempfile.mkdtemp()
    path = os.path.join(directory, "journal.json")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                             "machine": "m", "id": "e", "severity": "info",
                             "message": "x"}) + "\n")
    summary = summarize(path, since_days=30)
    check(not summary.truncated, "a journal with room to spare lost nothing")


def test_an_empty_journal_is_not_truncated_it_is_absent():
    """Two different nothings, and they must not read alike."""
    summary = summarize(os.path.join(tempfile.mkdtemp(), "never-written.json"))
    check(not summary.has_history, "never written is 'no history'")
    check(not summary.truncated, "which is NOT the same as trimmed")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
