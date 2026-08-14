"""Tests for the weekly guard digest (G12).

`build_digest` is pure, so the briefing is pinned without reading any files:
the device line, the persistent-attack callout, the what-changed section, and
the two honest empty-states (no history vs a quiet week). Plus the skill's day
parsing and an end-to-end run over a temp journal.

Run: python3 tools/test_digest.py
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.digest import build_digest  # noqa: E402
import skills.digest as digest_skill  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def test_device_line_and_changes():
    changes = [{"severity": "warning", "message": "New device on the LAN: .46",
                "count": 1, "last": "2026-07-24T10:00:00"}]
    out = build_digest("host", 15, 4, 1, changes, [], has_history=True, since_days=7)
    check("15 device(s) last seen · 4 with an open port · 1 critical" in out, "device summary line")
    check("New device on the LAN: .46" in out, "the change is listed")
    check("last 7 day(s)" in out, "the window is named")


def test_persistent_attack_is_called_out_first():
    persistent = [{"severity": "warning", "message": "ARP spoof suspected", "count": 5}]
    out = build_digest("host", 10, 0, 0, [], persistent, has_history=True)
    check("PERSISTENT" in out, "a persistent attack gets its own callout")
    check("ARP spoof suspected" in out and "5×" in out, "named with its count")
    check(out.index("PERSISTENT") < out.index("What changed"), "persistence leads")


def test_no_history_is_not_an_all_clear():
    out = build_digest("host", 0, 0, 0, [], [], has_history=False)
    check("No guard history yet" in out and "Not an all-clear" in out,
          "no journal → the patrol hasn't run, not 'the LAN is clean'")


def test_quiet_week_is_stated_plainly():
    out = build_digest("host", 12, 0, 0, [], [], has_history=True)
    check("Nothing moved" in out, "history exists but nothing changed → said plainly")


# --- the skill ------------------------------------------------------------

def test_skill_parses_a_day_count():
    check(digest_skill._days("digest 30") == 30, "reads an explicit day count")
    check(digest_skill._days("digest") == 7, "defaults to 7")


def test_skill_runs_over_a_temp_journal():
    base = tempfile.mkdtemp()
    os.chdir(base)
    os.makedirs(os.path.join("data", "census"), exist_ok=True)
    out = digest_skill.skill_digest("")            # no baselines, no journal
    check("WEEKLY DIGEST" in out, "produces a briefing")
    check("0 device(s)" in out and "No guard history yet" in out,
          "empty state is honest, not falsely clean")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
