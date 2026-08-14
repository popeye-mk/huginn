"""Baseline/diff (spec §6.1) — "what changed?" between two snapshots."""

import json
import os

from diffing import build_diff, diff_findings, diff_values
from interpreter import evaluate

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_diff_values_detects_disk_and_log_changes():
    old = load_fixture("healthy.json")
    new = load_fixture("dying_disk.json")

    changes = diff_values(old, new)
    joined = " ".join(changes)
    assert "Disk free space" in joined
    assert "Error log count" in joined


def test_diff_values_is_quiet_when_nothing_changed():
    snapshot = load_fixture("healthy.json")
    assert diff_values(snapshot, snapshot) == []


def test_diff_findings_reports_new_and_resolved():
    old = load_fixture("healthy.json")
    new = load_fixture("dying_disk.json")
    old_findings, _, _ = evaluate(old)
    new_findings, _, _ = evaluate(new)

    result = diff_findings(old_findings, new_findings)
    assert "disk_free_critical" in result["new_finding_ids"]
    assert "high_error_log_volume" in result["new_finding_ids"]
    assert result["resolved_finding_ids"] == []


def test_build_diff_combines_both():
    old = load_fixture("healthy.json")
    new = load_fixture("dying_disk.json")
    old_findings, _, _ = evaluate(old)
    new_findings, _, _ = evaluate(new)

    result = build_diff(old, new, old_findings, new_findings)
    assert result["value_changes"]
    assert result["new_finding_ids"]
    assert "resolved_finding_ids" in result
