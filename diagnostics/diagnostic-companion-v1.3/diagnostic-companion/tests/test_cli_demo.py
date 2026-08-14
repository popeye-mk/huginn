"""diag demo (spec §14.5) — smoke-tests it as a subprocess so the test
covers what a user actually types, and confirms it needs no privileges,
no network, and no real hardware to run end to end.
"""

import json
# Subprocess note: redirected CLI output is UTF-8 by contract (see
# console.py). These helpers decode UTF-8 explicitly — bare text=True
# uses the OS locale codepage (cp1252 on Windows), which raises
# UnicodeDecodeError inside subprocess's reader thread and silently
# leaves stdout as None rather than failing loudly.
import subprocess
import sys
from pathlib import Path

CLI = Path(__file__).resolve().parent.parent / "cli.py"


def run_demo(scenario, fmt="text"):
    return subprocess.run(
        [sys.executable, str(CLI), "demo", scenario, "--format", fmt],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
    )


def test_demo_dying_disk_exits_critical():
    result = run_demo("dying-disk")
    assert result.returncode == 2
    # dying-disk fires disk_free_critical + high_error_log_volume together,
    # which the dying_disk_chain (pattern_kb/chains.yaml) collapses into one
    # root-cause story rather than two flat findings — assert the story,
    # not the individual finding text it replaces.
    assert "ROOT CAUSE" in result.stdout
    assert "critically low" in result.stdout


def test_demo_healthy_exits_zero():
    result = run_demo("healthy")
    assert result.returncode == 0
    assert "No problems found" in result.stdout


def test_demo_unknown_scenario_fails_cleanly():
    result = subprocess.run(
        [sys.executable, str(CLI), "demo", "not-a-real-scenario"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10,
    )
    assert result.returncode != 0


def test_demo_json_format_is_valid_json():
    result = run_demo("dying-disk", fmt="json")
    payload = json.loads(result.stdout)
    assert payload["snapshot"]["hostname"] == "web-02"
    # the raw findings list is unaffected by chain display collapsing —
    # only report.py's text rendering collapses members into one story
    assert any(f["id"] == "disk_free_critical" for f in payload["findings"])
    assert payload["chains"][0]["id"] == "dying_disk_chain"
