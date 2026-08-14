"""Remediation and integrity tests (spec §14.3, §14.7, §13).

`diag fix` is the only non-read-only surface in the tool, so the tests
here are about what it *cannot* do, not what it can:
  - it cannot run a command that isn't in the code-reviewed whitelist
  - it cannot interpolate collected data into a command string
  - it cannot auto-suggest anything above risk:low
"""

import json
import os

import pytest

import fixes
from interpreter import evaluate

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def findings_for(name):
    return evaluate(load(name))[0]


# --- whitelist integrity ---------------------------------------------

def test_kb_fix_keys_are_all_whitelisted():
    """Loading raises if a KB entry names an unknown command."""
    fix_map = fixes.load_fix_map()
    for rule_id, key in fix_map.items():
        assert key in fixes.COMMAND_WHITELIST


def test_non_whitelisted_command_raises(tmp_path):
    """A KB edit must never be able to introduce a new command (§13)."""
    kb = tmp_path / "entries.yaml"
    kb.write_text(
        "- id: evil\n"
        "  match: { path: 'disk.data.min_free_percent', op: below, value: 10 }\n"
        "  finding: 'x'\n  severity: critical\n  confidence: certain\n"
        "  fix: 'rm -rf / --no-preserve-root'\n"
    )
    with pytest.raises(fixes.UnknownFixCommand):
        fixes.load_fix_map(str(kb))


def test_no_whitelisted_command_interpolates_data():
    """No command may contain a format placeholder (§13).

    If a command could be .format()ed, collected data could reach a
    shell. The whitelist is constant strings, and stays that way.
    """
    for key, spec in fixes.COMMAND_WHITELIST.items():
        for os_name in ("linux", "windows"):
            command = spec.get(os_name)
            if command:
                assert "{" not in command, f"{key}/{os_name} looks interpolatable"
                assert "%s" not in command


def test_only_low_risk_is_suggestible():
    findings = findings_for("dns_broken.json")
    plan = fixes.plan_fixes(findings, "linux")
    for item in plan:
        if item["suggestible"]:
            assert item["risk"] == "low"


def test_medium_risk_fix_is_advice_only():
    """gateway_unreachable maps to renew_dhcp (risk: medium)."""
    findings = [{"id": "gateway_unreachable", "finding": "gw down"}]
    plan = fixes.plan_fixes(findings, "linux")
    assert plan and plan[0]["risk"] == "medium"
    assert plan[0]["suggestible"] is False
    assert "Not auto-runnable" in fixes.render_plan(plan, "linux")


def test_plan_is_empty_when_no_finding_has_a_fix():
    plan = fixes.plan_fixes(findings_for("healthy.json"), "linux")
    assert plan == []
    assert "No whitelisted fixes apply" in fixes.render_plan(plan, "linux")


def test_render_says_dry_run_explicitly():
    plan = fixes.plan_fixes(findings_for("dying_disk.json"), "linux")
    assert "DRY RUN, nothing has been executed" in fixes.render_plan(plan, "linux")


def test_unsupported_os_yields_no_command_rather_than_a_wrong_one():
    findings = findings_for("dying_disk.json")
    assert fixes.plan_fixes(findings, "haiku-os") == []


# --- tamper evidence (§14.7) ------------------------------------------

def test_hash_is_stable_across_key_ordering():
    """The hash must cover content, not formatting."""
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert fixes.snapshot_hash(a) == fixes.snapshot_hash(b)


def test_stamped_snapshot_verifies():
    snapshot = fixes.stamp_snapshot(load("healthy.json"))
    ok, actual, expected = fixes.verify_snapshot(snapshot)
    assert ok is True and actual == expected


def test_tampering_is_detected():
    snapshot = fixes.stamp_snapshot(load("healthy.json"))
    snapshot["sections"]["disk"]["data"]["min_free_percent"] = 99
    ok, _, _ = fixes.verify_snapshot(snapshot)
    assert ok is False


def test_unstamped_snapshot_reports_unknown_not_ok():
    """No recorded hash is not the same as a valid one."""
    ok, actual, expected = fixes.verify_snapshot(load("healthy.json"))
    assert ok is None
    assert expected is None
    assert len(actual) == 64
