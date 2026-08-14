"""Fixture-based interpreter tests (spec §19 "Interpreter tests (fixtures)").

Every KB rule that's expected to fire in normal operation should have at
least one fixture proving it does — this is the cheap, fast, deterministic
half of the testing pyramid the spec calls for; golden/chaos/locale tests
are future work once there's more than one platform's worth of collectors.
"""

import json
import os

import pytest

from interpreter import evaluate, exit_code

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def finding_ids(findings):
    return {f["id"] for f in findings}


def test_healthy_snapshot_has_no_findings():
    snapshot = load_fixture("healthy.json")
    findings, worth_checking, not_checked = evaluate(snapshot)

    assert findings == []
    assert not_checked == []
    assert exit_code(findings) == 0


def test_dying_disk_fires_critical_disk_rule_not_the_warning_rule():
    snapshot = load_fixture("dying_disk.json")
    findings, worth_checking, not_checked = evaluate(snapshot)

    ids = finding_ids(findings)
    assert "disk_free_critical" in ids
    # supersedes: the warning-level rule must not also fire (§6 precedence)
    assert "disk_free_warning" not in ids

    assert "high_error_log_volume" in ids
    assert exit_code(findings) == 2  # certain + critical -> 2


def test_dying_disk_uptime_is_possible_confidence_not_a_headline():
    snapshot = load_fixture("dying_disk.json")
    findings, worth_checking, not_checked = evaluate(snapshot)

    assert "system_uptime_excessive" not in finding_ids(findings)
    assert "system_uptime_excessive" in finding_ids(worth_checking)


def test_dns_broken_fires_dns_rule_and_reports_skipped_logs_collector():
    snapshot = load_fixture("dns_broken.json")
    findings, worth_checking, not_checked = evaluate(snapshot)

    assert "dns_resolution_failing" in finding_ids(findings)
    assert "gateway_unreachable" not in finding_ids(findings)

    # absence is never health (§3.4): a skipped collector must be visible,
    # and must never silently produce a finding either
    not_checked_ids = {cid for cid, status, reason in not_checked}
    assert not_checked_ids == {"logs"}


def test_every_rule_id_referenced_in_tests_exists_in_kb():
    from interpreter import load_rules
    rule_ids = {r["id"] for r in load_rules()}
    expected = {
        "disk_free_critical", "disk_free_warning", "dns_resolution_failing",
        "gateway_unreachable", "high_error_log_volume", "system_uptime_excessive",
        "smart_reallocated", "battery_health_low", "wifi_weak",
    }
    assert expected <= rule_ids


def test_smart_reallocated_fires_as_critical():
    snapshot = load_fixture("smart_failing.json")
    findings, worth_checking, not_checked = evaluate(snapshot)

    assert "smart_reallocated" in finding_ids(findings)
    assert exit_code(findings) == 2


def test_log_threshold_does_not_fire_on_normal_linux_boot_noise():
    """Measured on a healthy Ubuntu 22.04 laptop: 20 benign boot errors.

    The original threshold of 10 fired on every healthy Linux desktop.
    A warning that is always present trains people to ignore warnings,
    including the real ones — so the threshold is set above measured
    normal rather than at a number that felt right.
    """
    import json
    import os

    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    with open(os.path.join(fixtures, "healthy.json"), encoding="utf-8") as f:
        snapshot = json.load(f)

    snapshot["sections"]["logs"]["data"]["error_count"] = 20
    fired = {f["id"] for f in evaluate(snapshot)[0]}
    assert "high_error_log_volume" not in fired


def test_log_threshold_still_catches_a_genuinely_noisy_machine():
    import json
    import os

    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    with open(os.path.join(fixtures, "healthy.json"), encoding="utf-8") as f:
        snapshot = json.load(f)

    snapshot["sections"]["logs"]["data"]["error_count"] = 45
    fired = {f["id"] for f in evaluate(snapshot)[0]}
    assert "high_error_log_volume" in fired
