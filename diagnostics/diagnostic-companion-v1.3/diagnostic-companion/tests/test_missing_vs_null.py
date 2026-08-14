"""Missing data is not null data (spec §3.4).

A rule written `{op: equals, value: null}` should fire when a collector
reports `gateway: null` — it looked, and there is no gateway. It must
NOT fire when the collector never reported a `gateway` field at all.

These are separate facts and collapsing them makes a rule fire on every
machine whose collector predates the field, which is precisely how a
diagnostic tool becomes confidently wrong.
"""

import json
import os

import pytest

import policy
from interpreter import MISSING, _get_by_path, evaluate

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

NULL_GATEWAY_RULE = [{
    "id": "no_default_gateway",
    "match": {"path": "network.data.gateway", "op": "equals", "value": None},
    "finding": "No default gateway is configured.",
    "severity": "critical",
    "confidence": "certain",
    "next_step": "check DHCP",
}]


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


def test_path_resolver_distinguishes_missing_from_null():
    snapshot = {"sections": {"network": {"status": "ok", "data": {"gateway": None}}}}
    assert _get_by_path(snapshot, "sections.network.data.gateway") is None
    assert _get_by_path(snapshot, "sections.network.data.nope") is MISSING


def test_explicit_null_fires_the_rule():
    snapshot = load("no_gateway.json")
    findings, _, _ = evaluate(snapshot, NULL_GATEWAY_RULE)
    assert [f["id"] for f in findings] == ["no_default_gateway"]


def test_absent_field_does_not_fire_the_rule():
    """The regression this whole module exists for."""
    snapshot = load("no_gateway.json")
    del snapshot["sections"]["network"]["data"]["gateway"]

    findings, worth, _ = evaluate(snapshot, NULL_GATEWAY_RULE)
    assert findings == []
    assert worth == []


def test_healthy_fleet_asset_does_not_report_a_missing_gateway():
    """healthy.json has no `gateway` key at all — it must stay clean."""
    findings, worth, _ = evaluate(load("healthy.json"))
    assert "no_default_gateway" not in {f["id"] for f in findings + worth}


def test_policy_treats_a_missing_field_as_unknown_not_pass():
    snapshot = load("healthy.json")
    del snapshot["sections"]["disk"]["data"]["min_free_percent"]

    results = policy.check(snapshot)
    disk = next(r for r in results if r["rule"] == "disk_space_available")
    assert disk["outcome"] == "unknown"
    assert policy.policy_exit_code(results) != 0
