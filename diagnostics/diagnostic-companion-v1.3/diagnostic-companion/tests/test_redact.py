"""--anon redaction (spec §4.3, §5) — "tested like a security control,
not a feature." Two kinds of test here: a fixture seeded with every
known sensitive pattern must come out clean, and every active collector
must have a registered redaction decision (no silent pass-through).
"""

import json
import os

import pytest

import cli
from redact import SECTION_REDACTORS, redact_snapshot

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


def test_hostname_is_masked_and_no_longer_literal():
    snapshot = load_fixture("sensitive_data.json")
    redacted = redact_snapshot(snapshot)

    assert redacted["hostname"] != "jdoe-laptop"
    assert redacted["hostname"].startswith("host-")
    assert "jdoe" not in redacted["hostname"]


def test_hostname_masking_is_stable_across_calls():
    """So multiple redacted reports from the same machine can still be
    recognised as the same machine without revealing its name."""
    snapshot = load_fixture("sensitive_data.json")
    a = redact_snapshot(snapshot)
    b = redact_snapshot(snapshot)
    assert a["hostname"] == b["hostname"]


def test_public_dns_server_is_masked_private_gateway_is_kept():
    snapshot = load_fixture("sensitive_data.json")
    redacted = redact_snapshot(snapshot)
    net = redacted["sections"]["network"]["data"]

    assert "8.8.8.8" not in net["dns_servers"]
    # 192.168.1.1 appears twice in the fixture (as a DNS server entry and
    # as the gateway) — both are private-range and both should be kept,
    # by design: private IPs are needed to troubleshoot a LAN and don't
    # identify a person the way a public IP does (see redact.py docstring).
    assert "192.168.1.1" in net["dns_servers"]
    assert net["gateway"] == "192.168.1.1"


def test_ssid_is_masked():
    snapshot = load_fixture("sensitive_data.json")
    redacted = redact_snapshot(snapshot)
    ssid = redacted["sections"]["wifi"]["data"]["adapters"][0]["ssid"]

    assert ssid != "JohnDoe-HomeNetwork"
    assert ssid.startswith("ssid-")


def test_log_entries_scrub_ip_mac_email_and_home_path():
    snapshot = load_fixture("sensitive_data.json")
    redacted = redact_snapshot(snapshot)
    entries = " ".join(redacted["sections"]["logs"]["data"]["entries"])

    assert "8.8.4.4" not in entries
    assert "aa:bb:cc:dd:ee:ff" not in entries
    assert "jdoe@example.com" not in entries
    assert "/home/jdoe/" not in entries
    # the surrounding log text should survive, only the sensitive tokens change
    assert "Failed password" in entries
    assert "lease renewed" in entries


def test_disk_and_system_data_pass_through_unchanged():
    """Nothing in disk/system data is personal — redaction shouldn't
    touch it, and a redaction test suite should prove that too, not
    just prove the sensitive fields get caught."""
    snapshot = load_fixture("sensitive_data.json")
    redacted = redact_snapshot(snapshot)

    assert redacted["sections"]["disk"]["data"] == snapshot["sections"]["disk"]["data"]
    assert redacted["sections"]["system"]["data"] == snapshot["sections"]["system"]["data"]


def test_original_snapshot_is_not_mutated():
    snapshot = load_fixture("sensitive_data.json")
    original_hostname = snapshot["hostname"]
    redact_snapshot(snapshot)
    assert snapshot["hostname"] == original_hostname


def test_every_active_linux_collector_has_a_registered_redaction_rule():
    """The completeness check: a new collector must ship with a
    redaction decision, not rely on redact_snapshot's runtime raise to
    catch it later. This is the CI-time equivalent of that guard."""
    collector_ids = {name for name, _func, _timeout, _priv in
                      cli.CORE_COLLECTORS + cli.OPTIONAL_COLLECTORS}
    missing = collector_ids - set(SECTION_REDACTORS)
    assert not missing, f"collectors with no redaction rule: {missing}"


def test_redact_snapshot_raises_on_unregistered_section():
    snapshot = load_fixture("healthy.json")
    snapshot["sections"]["mystery_collector"] = {
        "status": "ok", "reason": None, "duration_ms": 1,
        "privilege_level": "unprivileged", "data": {"anything": "here"},
    }
    with pytest.raises(RuntimeError, match="No redaction rule registered"):
        redact_snapshot(snapshot)
