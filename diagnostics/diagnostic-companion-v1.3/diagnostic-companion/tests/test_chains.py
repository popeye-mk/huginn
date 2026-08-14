"""Root-cause chains (spec §14.1) — display-layer consolidation only."""

import json
import os

from interpreter import evaluate, resolve_chains

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_dying_disk_chain_fires_and_consumes_both_members():
    snapshot = load_fixture("dying_disk.json")
    findings, _worth_checking, _not_checked = evaluate(snapshot)

    chains, remaining = resolve_chains(findings)

    assert len(chains) == 1
    assert chains[0]["id"] == "dying_disk_chain"
    assert set(chains[0]["members"]) == {"disk_free_critical", "high_error_log_volume"}

    remaining_ids = {f["id"] for f in remaining}
    assert "disk_free_critical" not in remaining_ids
    assert "high_error_log_volume" not in remaining_ids


def test_partial_evidence_does_not_fire_a_chain():
    """dns_broken.json only has dns_resolution_failing, not
    gateway_unreachable — network_link_down_chain needs both. Incomplete
    evidence must degrade to the flat list, never invent a narrative."""
    snapshot = load_fixture("dns_broken.json")
    findings, _worth_checking, _not_checked = evaluate(snapshot)

    chains, remaining = resolve_chains(findings)

    assert chains == []
    assert remaining == findings


def test_healthy_snapshot_has_no_chains():
    snapshot = load_fixture("healthy.json")
    findings, _worth_checking, _not_checked = evaluate(snapshot)

    chains, remaining = resolve_chains(findings)
    assert chains == []
    assert remaining == []


def test_chain_never_consumes_a_possible_confidence_finding():
    """system_uptime_excessive (possible) is present in dying_disk.json's
    worth_checking, not findings — it must never be eligible for a chain."""
    snapshot = load_fixture("dying_disk.json")
    findings, worth_checking, _not_checked = evaluate(snapshot)

    assert "system_uptime_excessive" not in {f["id"] for f in findings}
    assert "system_uptime_excessive" in {f["id"] for f in worth_checking}
