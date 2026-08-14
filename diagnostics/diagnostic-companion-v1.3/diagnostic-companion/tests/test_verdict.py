"""Verdict tests (spec §3.4, §14.2, §15.11).

The headline is the part people quote, so the honesty rules bite
hardest here. The load-bearing assertion in this module is that a
verdict can never claim health over partial coverage.
"""

import json
import os

import pytest

from interpreter import evaluate, resolve_chains
from verdict import build_verdict

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def verdict_for(name):
    snapshot = load(name)
    findings, _worth, not_checked = evaluate(snapshot)
    chains, _remaining = resolve_chains(findings)
    return build_verdict(findings, not_checked, chains)


def test_healthy_full_coverage_says_no_problems_found():
    v = verdict_for("healthy.json")
    assert v["level"] == "ok"
    assert v["headline"] == "No problems found"
    assert v["coverage_caveat"] is None


def test_healthy_with_gaps_never_claims_a_clean_bill_of_health():
    """The whole point of this module (§3.4)."""
    snapshot = load("healthy.json")
    snapshot["sections"]["disk"] = {
        "status": "skipped", "reason": "not privileged", "duration_ms": 0,
        "privilege_level": "unprivileged", "data": {},
    }
    findings, _worth, not_checked = evaluate(snapshot)
    v = build_verdict(findings, not_checked)

    assert v["level"] == "ok"
    assert v["headline"] == "No problems found in what could be checked"
    assert "not a clean bill of health" in v["detail"]
    assert v["coverage_caveat"] and "disk" in v["coverage_caveat"]


def test_critical_finding_drives_a_critical_verdict():
    v = verdict_for("dying_disk.json")
    assert v["level"] == "critical"
    assert v["action"]


def test_chain_becomes_the_headline_when_one_fires():
    v = verdict_for("dying_disk.json")
    assert v["headline"] == "One underlying problem explains several symptoms"
    assert "disk" in v["detail"].lower()


def test_warning_only_snapshot_is_not_escalated():
    v = verdict_for("disk_warning.json")
    assert v["level"] == "warning"
    assert "Not urgent" in v["detail"]


def test_multiple_criticals_are_counted_in_the_headline():
    snapshot = load("link_down.json")
    findings, _worth, not_checked = evaluate(snapshot)
    v = build_verdict(findings, not_checked)
    assert v["level"] == "critical"
    assert "other critical issue" in v["headline"]


def test_verdict_always_has_the_required_shape():
    for fixture in ("healthy.json", "dying_disk.json", "resource_pressure.json",
                    "worn_laptop.json", "no_gateway.json"):
        v = verdict_for(fixture)
        assert set(v) == {"level", "headline", "detail", "action", "coverage_caveat"}
        assert v["level"] in {"ok", "warning", "critical"}
        assert v["headline"] and v["detail"]
