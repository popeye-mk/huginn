"""Tests for the scheduled codebase-health check (B3).

`build_report` is pure, so its verdict is pinned without running the guards:
healthy only when architecture + fork-boundary pass AND the answer anchor
holds; a regressed anchor or a failed guard flips it to NEEDS ATTENTION; and a
missing corpus is reported as "not checked", never quietly counted as a pass.

Run: python3 tools/test_codebase_health.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.codebase_health import build_report  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def test_all_green_is_healthy():
    ok, text = build_report(True, True, 36, 0, "abc123")
    check(ok is True, "arch+boundary+anchor all good → healthy")
    check("CODEBASE HEALTH — OK" in text, "header says OK")
    check("36/52 ok" in text, "anchor line shows the number")


def test_a_failed_guard_flips_it():
    check(build_report(False, True, 36, 0, "x")[0] is False, "architecture FAIL → not healthy")
    check(build_report(True, False, 36, 0, "x")[0] is False, "boundary FAIL → not healthy")
    ok, text = build_report(True, True, 36, 0, "x")
    check("NEEDS ATTENTION" not in text, "healthy report is not flagged")


def test_a_regressed_anchor_flips_it():
    ok, text = build_report(True, True, 35, 0, "x")
    check(ok is False, "anchor below the floor → not healthy")
    check("REGRESSED" in text, "the regression is named")


def test_missing_corpus_is_not_a_pass_but_not_a_structural_fail():
    ok, text = build_report(True, True, None, 3, "x")
    check("not checked" in text and "NOT a pass" in text,
          "no corpus → reported honestly, never silently passed")
    check(ok is True, "structural health does not depend on the operator's private corpus")


def test_uncommitted_count_is_reported():
    _, text = build_report(True, True, 36, 7, "deadbee")
    check("7 uncommitted file(s)" in text and "deadbee" in text, "git state shown")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
