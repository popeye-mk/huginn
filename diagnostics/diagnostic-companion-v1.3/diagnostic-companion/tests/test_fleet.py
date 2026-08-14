"""Fleet correlation and health score tests (spec §8, §14.6).

The denominator is the whole point. An asset that couldn't check the
relevant collector must be excluded from both the numerator and the
denominator — counting it as healthy would make "4 of 6" a lie in the
most confidence-inspiring possible format.
"""

import copy
import glob
import json
import os

import pytest

import fleet

FLEET_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "fleet")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fleet():
    return fleet.load_snapshots(sorted(glob.glob(os.path.join(FLEET_DIR, "*.json"))))


def load(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


# --- correlation ------------------------------------------------------

def test_shared_finding_is_correlated():
    results = fleet.correlate(load_fleet())
    dns = next(r for r in results if r["finding_id"] == "dns_resolution_failing")
    assert dns["affected"] == 4
    assert dns["environment_level"] is True


def test_asset_with_skipped_collector_is_in_neither_number():
    """The load-bearing test for §8."""
    results = fleet.correlate(load_fleet())
    dns = next(r for r in results if r["finding_id"] == "dns_resolution_failing")

    assert "ws-06" not in dns["hostnames"]
    assert "ws-06" in dns["excluded"]
    assert dns["checked"] == 5, "the excluded asset must not inflate the denominator"


def test_excluded_assets_are_named_not_just_counted():
    results = fleet.correlate(load_fleet())
    dns = next(r for r in results if r["finding_id"] == "dns_resolution_failing")
    assert dns["excluded"] == ["ws-06"]


def test_single_asset_finding_is_not_environment_level():
    """One machine with a full disk is not a fleet-wide conclusion."""
    results = fleet.correlate(load_fleet())
    disk = next(r for r in results if r["finding_id"] == "disk_free_critical")
    assert disk["affected"] == 1
    assert disk["environment_level"] is False


def test_two_of_two_is_not_a_pattern():
    """A majority of a tiny sample is a coincidence, not a conclusion."""
    a = load("dns_broken.json")
    a["hostname"] = "a"
    b = copy.deepcopy(a)
    b["hostname"] = "b"

    results = fleet.correlate([a, b])
    dns = next(r for r in results if r["finding_id"] == "dns_resolution_failing")
    assert dns["affected"] == 2
    assert dns["environment_level"] is False


def test_correlation_of_an_empty_fleet_is_empty():
    assert fleet.correlate([]) == []


# --- health score -----------------------------------------------------

def test_healthy_asset_scores_100():
    assert fleet.health_score(load("healthy.json"))["score"] == 100


def test_score_is_explained_by_its_deductions():
    """§14.6 — the number must be defensible by construction."""
    result = fleet.health_score(load("dying_disk.json"))
    assert result["deductions"], "a score below 100 with no listed reasons is a black box"
    assert result["score"] == 100 - sum(d["amount"] for d in result["deductions"])
    for d in result["deductions"]:
        assert d["reason"] and d["id"]


def test_score_never_goes_negative():
    snapshot = load("resource_pressure.json")
    assert fleet.health_score(snapshot)["score"] >= 0


def test_partial_coverage_is_reported_alongside_the_score():
    """A score over partial data is a different claim (§3.4, §14.6)."""
    snapshot = load("healthy.json")
    snapshot["sections"]["disk"] = {
        "status": "skipped", "reason": "not privileged", "duration_ms": 0,
        "privilege_level": "unprivileged", "data": {},
    }
    result = fleet.health_score(snapshot)
    assert result["checked"] < result["total"]
    assert result["coverage"] == f"{result['checked']}/{result['total']} checked"


def test_render_names_the_excluded_assets():
    text = fleet.render_fleet(load_fleet())
    assert "not counted as healthy" in text
    assert "ws-06" in text


def test_render_shows_the_worst_assets_breakdown():
    text = fleet.render_fleet(load_fleet())
    assert "Score = 100 minus listed deductions" in text


def test_load_snapshots_skips_non_snapshots(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(load("healthy.json")))
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "other.json").write_text('{"unrelated": true}')

    loaded = fleet.load_snapshots(sorted(glob.glob(str(tmp_path / "*.json"))))
    assert len(loaded) == 1
