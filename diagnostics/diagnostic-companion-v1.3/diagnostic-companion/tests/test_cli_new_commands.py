"""Subprocess tests for the commands added after the walking skeleton.

Run exactly as a user would, so argparse wiring, imports and exit codes
are all covered — a unit test on the module can't catch a broken
--format choice or a missing import in cli.py.
"""

import json
import os
# Subprocess note: redirected CLI output is UTF-8 by contract (see
# console.py). These helpers decode UTF-8 explicitly — bare text=True
# uses the OS locale codepage (cp1252 on Windows), which raises
# UnicodeDecodeError inside subprocess's reader thread and silently
# leaves stdout as None rather than failing loudly.
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "cli.py")
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "dying_disk.json")


def run(*args):
    return subprocess.run(
        [sys.executable, CLI, *args], capture_output=True, cwd=ROOT,
        # The CLI forces UTF-8 whenever output is redirected, so decode
        # UTF-8 explicitly. text=True, encoding="utf-8", errors="replace" would use the OS locale codepage
        # (cp1252 on Windows), which raises UnicodeDecodeError in
        # subprocess's reader thread and silently yields stdout=None.
        text=True, encoding="utf-8", errors="replace"
    )


def test_demo_html_is_valid_single_file():
    proc = run("demo", "dying-disk", "--format", "html")
    assert proc.returncode == 2  # critical finding
    assert proc.stdout.startswith("<!doctype html>")
    assert proc.stdout.rstrip().endswith("</html>")


def test_html_stdout_stays_pure_when_banner_prints():
    """The demo banner goes to stderr so stdout is a usable .html file."""
    proc = run("demo", "dying-disk", "--format", "html")
    assert "[demo:" in proc.stderr
    assert "[demo:" not in proc.stdout


def test_policy_check_against_saved_snapshot():
    proc = run("policy", "check", "--snapshot", FIXTURE)
    assert proc.returncode == 2
    assert "Policy check" in proc.stdout
    assert "NOT counted as compliant" in proc.stdout


def test_policy_json_is_parseable():
    proc = run("policy", "check", "--snapshot", FIXTURE, "--format", "json")
    payload = json.loads(proc.stdout)
    assert set(payload["summary"]) == {"pass", "fail", "unknown"}


def test_fix_defaults_to_dry_run_and_exits_clean():
    proc = run("fix", "--snapshot", FIXTURE)
    assert proc.returncode == 0
    assert "DRY RUN" in proc.stdout


def test_verify_reports_missing_hash_without_claiming_valid():
    proc = run("verify", FIXTURE)
    assert proc.returncode == 1
    assert "No integrity hash" in proc.stdout


def test_verify_detects_tampering(tmp_path):
    import fixes
    with open(FIXTURE) as f:
        snapshot = json.load(f)
    fixes.stamp_snapshot(snapshot)

    good = tmp_path / "good.json"
    good.write_text(json.dumps(snapshot))
    assert run("verify", str(good)).returncode == 0

    snapshot["hostname"] = "someone-else"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(snapshot))
    proc = run("verify", str(bad))
    assert proc.returncode == 2
    assert "MISMATCH" in proc.stderr


def test_why_unknown_symptom_falls_back_rather_than_erroring():
    proc = run("why", "not-a-real-symptom")
    assert proc.returncode in (0, 1, 2)  # a real run happened
    assert "running a full diagnostic instead" in proc.stderr


def test_why_reports_collectors_it_deliberately_skipped():
    """§3.4 — a narrowed run must say what it did not look at."""
    proc = run("why", "battery")
    assert "not relevant to symptom 'battery'" in proc.stdout


# --- fleet / decode / kb lint ----------------------------------------

FLEET_DIR = os.path.join(ROOT, "tests", "fixtures", "fleet")


def test_kb_lint_passes_on_the_shipped_kb():
    """A dirty KB must fail the build, so this must pass in CI."""
    proc = run("kb", "lint")
    assert proc.returncode == 0, proc.stdout
    assert "Knowledge base is clean" in proc.stdout


def test_fleet_reports_environment_level_conclusion():
    proc = run("fleet", FLEET_DIR)
    assert "Environment-level conclusions" in proc.stdout
    assert "open ONE ticket" in proc.stdout
    assert proc.returncode == 1  # something shared is upstream


def test_fleet_json_is_parseable():
    proc = run("fleet", FLEET_DIR, "--format", "json")
    payload = json.loads(proc.stdout)
    assert payload["assets"] and payload["correlations"]
    assert all("coverage" in a for a in payload["assets"])


def test_fleet_on_a_single_healthy_asset_exits_clean():
    healthy = os.path.join(ROOT, "tests", "fixtures", "healthy.json")
    proc = run("fleet", healthy)
    assert proc.returncode == 0


def test_decode_known_code():
    proc = run("decode", "0x80070005")
    assert proc.returncode == 0
    assert "Access denied" in proc.stdout


def test_decode_unknown_code_exits_nonzero():
    """'I have nothing useful to say' is not success."""
    proc = run("decode", "0xdeadbeef")
    assert proc.returncode == 1
    assert "Unknown code" in proc.stdout


def test_decode_list_shows_every_code():
    proc = run("decode", "--list")
    assert proc.returncode == 0
    assert "windows_update" in proc.stdout and "bsod" in proc.stdout
