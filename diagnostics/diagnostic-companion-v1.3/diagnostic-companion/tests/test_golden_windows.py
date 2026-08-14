"""Golden tests against REAL Windows output (spec §19).

tests/golden/win11_26200_ps51.json holds verbatim PowerShell output
captured from a live Windows 11 Pro machine (build 26200, PowerShell
5.1) via tools/capture_windows_golden.py. Everything here runs the
shipped parsers against that evidence.

This is the difference between "the parser handles the shape I imagined"
and "the parser handles the shape Windows actually emits". Every
assertion below is a fact about a real machine, not an invention.
"""

import json
import os
from datetime import datetime, timezone

import pytest

import decoder
from collectors.windows import disk as win_disk
from collectors.windows import logs as win_logs
from collectors.windows import network as win_network
from collectors.windows import system as win_system

GOLDEN = os.path.join(os.path.dirname(__file__), "golden", "win11_26200_ps51.json")


@pytest.fixture(scope="module")
def golden():
    with open(GOLDEN) as f:
        return json.load(f)


# --- system -----------------------------------------------------------

def test_system_parses_real_output(golden):
    data = win_system.parse(golden["system"])
    assert data["os_release"] == "Microsoft Windows 11 Pro"
    assert data["kernel"] == "10.0.26200"
    assert data["mem_total_mb"] == 4076.4
    assert data["mem_used_percent"] == 66.0


def test_system_uptime_from_ps51_date_format(golden):
    """PowerShell 5.1 emits /Date(epoch_ms)/ — the shape that kept
    uptime unimplemented until a real machine confirmed it.

    Both the boot time and the capture instant are real values from the
    machine, so this asserts the exact uptime that run reported rather
    than one computed from an invented timestamp.
    """
    now = datetime.fromtimestamp(golden["_captured_at_epoch"], tz=timezone.utc)
    data = win_system.parse(golden["system"], now=now)

    assert data["last_boot"] == "2026-07-20T08:04:20+00:00"
    assert data["last_boot_epoch"] == 1784534660
    assert data["uptime_seconds"] == pytest.approx(4866.5, abs=1)
    assert data["uptime_days"] == 0.1


def test_uptime_is_absent_rather_than_negative_on_clock_skew(golden):
    """A boot time in the future means the clock moved, not that uptime
    is negative. Clock drift is itself diagnosable; a negative uptime
    would mask it behind nonsense."""
    past = datetime.fromtimestamp(1784530000, tz=timezone.utc)
    data = win_system.parse(golden["system"], now=past)
    assert "uptime_days" not in data
    assert "last_boot" not in data


def test_system_omits_uptime_rather_than_guessing(golden):
    """An unparseable boot time must leave the field absent, not null.

    The interpreter treats missing and null differently; a null uptime
    could match a rule, an absent one cannot (§3.4).
    """
    raw = json.loads(golden["system"])
    raw["LastBootUpTime"] = "something unexpected"
    data = win_system.parse(json.dumps(raw))
    assert "uptime_days" not in data


# --- disk -------------------------------------------------------------

def test_disk_parses_single_volume_collapsed_to_an_object(golden):
    """One fixed disk: ConvertTo-Json emits a bare object, not an array."""
    data = win_disk.parse(golden["disk"])
    assert len(data["volumes"]) == 1
    assert data["volumes"][0]["device"] == "C:"
    assert data["volumes"][0]["fstype"] == "NTFS"
    assert data["volumes"][0]["total_gb"] == 49.06
    assert data["min_free_percent"] == 41.0


# --- network ----------------------------------------------------------

def test_network_parses_real_output(golden):
    """The highest-risk collector: five chained cmdlets."""
    data = win_network.parse(golden["network"])
    assert data["interface"] == "Ethernet"
    assert data["gateway"] == "192.168.122.1"
    assert data["dns_servers"] == ["192.168.122.1"]
    assert data["dns_any_failed"] is False
    assert data["gateway_ping"]["reachable"] is True


def test_network_dns_hashtable_survives_serialisation(golden):
    """A PowerShell hashtable round-trips as a JSON object, not an array."""
    data = win_network.parse(golden["network"])
    assert set(data["dns_resolution"]) == {"example.com", "cloudflare.com", "wikipedia.org"}
    assert all(v is True for v in data["dns_resolution"].values())


# --- logs -------------------------------------------------------------

def test_logs_count_is_real_not_the_sample_size(golden):
    data = win_logs.parse(golden["logs"])
    assert data["error_count"] == 7
    assert data["window_hours"] == 24


def test_log_timestamps_are_readable_iso_not_ps_date_wrappers(golden):
    """/Date(1784538433261)/ is not something to show a technician."""
    data = win_logs.parse(golden["logs"])
    first = data["entries"][0]
    assert "/Date(" not in first
    assert first.startswith("2026-07-20T")


def test_log_messages_have_crlf_collapsed(golden):
    """Real messages contain CRLF mid-sentence; one entry is one line."""
    data = win_logs.parse(golden["logs"])
    joined = " ".join(data["entries"])
    assert "\r" not in joined and "\n" not in joined
    assert "  " not in joined, "run-on whitespace should be collapsed"
    assert any("A system shutdown is in progress." in e for e in data["entries"])


# --- decoder integration ----------------------------------------------

def test_real_update_failure_code_is_decoded_from_log_text(golden):
    """The end-to-end §10 moment, driven by a code from a real machine."""
    snapshot = {"sections": {"logs": {"status": "ok", "data": win_logs.parse(golden["logs"])}}}
    hits = decoder.scan_snapshot(snapshot)

    assert len(hits) == 1
    assert hits[0]["code"] == "0x80073d02"
    assert "currently in use" in hits[0]["meaning"]


def test_decoder_ignores_the_dcom_guid_in_the_same_logs(golden):
    """{A47979D2-C419-11D9-...} must not be mistaken for an error code.

    The real capture contains a DCOM GUID alongside a genuine update
    failure code. A decoder that fires on any hex-looking string would
    produce confident nonsense here.
    """
    snapshot = {"sections": {"logs": {"status": "ok", "data": win_logs.parse(golden["logs"])}}}
    hits = decoder.scan_snapshot(snapshot)
    assert all("A47979D2" not in h["code"].upper() for h in hits)


def test_scan_skips_logs_that_did_not_run():
    """No data, no decoding (§3.4)."""
    snapshot = {"sections": {"logs": {"status": "skipped", "reason": "x", "data": {}}}}
    assert decoder.scan_snapshot(snapshot) == []


# --- whole-snapshot sanity --------------------------------------------

def test_golden_snapshot_produces_a_clean_interpretation(golden):
    """7 errors is under the threshold of 10 — this machine is healthy."""
    from interpreter import evaluate, exit_code

    snapshot = {
        "schema_version": "0.1.0",
        "collected_at": "2026-07-20T09:16:42+00:00",
        "hostname": "DESKTOP-EVDIR2D",
        "os": "windows",
        "sections": {
            name: {"status": "ok", "reason": None, "duration_ms": 1,
                   "privilege_level": "unprivileged", "data": parser(golden[name])}
            for name, parser in [
                ("system", win_system.parse), ("disk", win_disk.parse),
                ("network", win_network.parse), ("logs", win_logs.parse),
            ]
        },
    }
    findings, worth, not_checked = evaluate(snapshot)

    assert findings == [], f"unexpected findings on a healthy machine: {findings}"
    assert not_checked == []
    assert exit_code(findings) == 0
