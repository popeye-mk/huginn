"""Triage tests (spec §7).

The safety property under test: narrowing a run must *grow* the
"Not checked" list, never shrink it. A faster answer that quietly
reduces its own scope is the exact failure mode §3.4 exists to prevent.
"""

import json
import os

import pytest

import triage
from interpreter import evaluate

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
AVAILABLE = [
    ("system", None, 10, "unprivileged"),
    ("network", None, 10, "unprivileged"),
    ("disk", None, 10, "unprivileged"),
    ("logs", None, 10, "unprivileged"),
    ("battery", None, 10, "unprivileged"),
    ("wifi", None, 10, "unprivileged"),
    ("smart", None, 30, "elevated"),
]


def test_known_symptoms_load():
    symptoms = triage.known_symptoms()
    assert "slow" in symptoms and "no-internet" in symptoms


def test_unknown_symptom_returns_none_for_fallback():
    """Unknown symptom must not raise — the CLI falls back to a full run."""
    assert triage.get_profile("banana") is None


def test_selection_and_exclusion_partition_the_collector_set():
    """Every available collector is either run or explicitly excluded."""
    profile = triage.get_profile("no-internet")
    selected = {e[0] for e in triage.select_collectors(profile, AVAILABLE)}
    excluded = set(triage.excluded_collectors(profile, AVAILABLE))

    assert selected & excluded == set(), "a collector cannot be both run and skipped"
    assert selected | excluded == {e[0] for e in AVAILABLE}, "a collector vanished"


def test_narrowing_never_silently_drops_a_collector():
    """The core §3.4 property, asserted for every profile in the KB."""
    for profile in triage.load_profiles():
        excluded = triage.excluded_collectors(profile, AVAILABLE)
        selected = triage.select_collectors(profile, AVAILABLE)
        assert len(excluded) + len(selected) == len(AVAILABLE)


def test_profile_collectors_all_exist():
    """A typo in triage.yaml would silently narrow a run to nothing."""
    known = {e[0] for e in AVAILABLE}
    for profile in triage.load_profiles():
        unknown = set(profile["collectors"]) - known
        assert not unknown, f"{profile['symptom']} references unknown collectors: {unknown}"


def test_weighted_rule_ids_exist_in_kb():
    """Weighting a rule id that no longer exists is dead config."""
    from interpreter import load_rules
    known_ids = {r["id"] for r in load_rules()}
    for profile in triage.load_profiles():
        unknown = set(profile.get("weight", [])) - known_ids
        assert not unknown, f"{profile['symptom']} weights unknown rules: {unknown}"


def test_prioritise_reorders_but_never_changes_the_set():
    """Weighting is display-only (§16) — same findings, different order."""
    with open(os.path.join(FIXTURES, "dying_disk.json")) as f:
        snapshot = json.load(f)
    findings, _, _ = evaluate(snapshot)

    profile = {"symptom": "x", "collectors": [], "weight": ["high_error_log_volume"]}
    reordered = triage.prioritise(findings, profile)

    assert {f["id"] for f in reordered} == {f["id"] for f in findings}
    assert len(reordered) == len(findings)
    # the weighted id leads, even though it is only a warning and the
    # other finding is critical
    assert reordered[0]["id"] == "high_error_log_volume"
