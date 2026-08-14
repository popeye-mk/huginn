"""Policy tests (spec §9).

The whole module exists to make `unknown` a first-class outcome. These
tests exist to make sure it stays that way — a refactor that folds
unknown into pass would otherwise pass every other test in the suite.
"""

import json
import os

import pytest

import policy

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def test_healthy_snapshot_has_no_failures():
    results = policy.check(load("healthy.json"))
    assert not [r for r in results if r["outcome"] == "fail"]


def test_dying_disk_fails_the_disk_rule():
    results = policy.check(load("dying_disk.json"))
    by_rule = {r["rule"]: r for r in results}
    assert by_rule["disk_space_available"]["outcome"] == "fail"
    assert by_rule["disk_space_available"]["severity"] == "critical"


def test_skipped_collector_is_unknown_never_pass():
    """The load-bearing test for this module (§9)."""
    snapshot = load("healthy.json")
    snapshot["sections"]["disk"] = {
        "status": "skipped", "reason": "not privileged",
        "duration_ms": 0, "privilege_level": "unprivileged", "data": {},
    }
    results = policy.check(snapshot)
    disk_rule = next(r for r in results if r["rule"] == "disk_space_available")

    assert disk_rule["outcome"] == "unknown"
    assert disk_rule["outcome"] != "pass"
    assert "not privileged" in disk_rule["detail"]


def test_unknown_can_never_produce_a_clean_exit_code():
    """A run that couldn't check everything is not a compliant run."""
    snapshot = load("healthy.json")
    snapshot["sections"]["network"]["status"] = "timeout"
    snapshot["sections"]["network"]["reason"] = "timed out after 10s"

    results = policy.check(snapshot)
    assert policy.policy_exit_code(results) != 0


def test_critical_failure_exits_2():
    assert policy.policy_exit_code(policy.check(load("dying_disk.json"))) == 2


def test_summary_counts_add_up():
    results = policy.check(load("dying_disk.json"))
    counts = policy.summarise(results)
    assert sum(counts.values()) == len(results)


def test_render_names_unknowns_explicitly():
    """The report must say out loud that unknowns are not compliance."""
    snapshot = load("healthy.json")
    snapshot["sections"]["disk"]["status"] = "error"
    snapshot["sections"]["disk"]["reason"] = "boom"
    text = policy.render_policy(policy.check(snapshot))

    assert "NOT counted as compliant" in text
    assert "disk_space_available" in text
