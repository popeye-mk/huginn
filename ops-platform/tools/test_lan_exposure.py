"""Tests for the LAN exposure scan (G2) — engine parse + domain meaning.

A live scan can't run in a test, so the nmap parser is pinned against
captured output and the domain's severity/newly-opened logic is exercised
against constructed scan results. Every test is a claim about meaning:
telnet is critical, a newly-opened port is called out, and a device that
answered nothing produces no false "secure".

Run: python3 tools/test_lan_exposure.py
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.exposure import (  # noqa: E402
    ack_id, add_ack, assess, load_acks, load_exposure_baseline,
    save_acks, save_exposure_baseline,
)
from engines.lan_exposure import DANGEROUS_PORTS, _parse_nmap  # noqa: E402


def test_dangerous_set_covers_the_classics():
    for port in (23, 445, 3389, 5900, 21):
        assert port in DANGEROUS_PORTS


def test_parse_nmap_pulls_open_ports():
    text = ("Nmap scan report for 192.168.1.5\n"
            "445/tcp open  microsoft-ds\n"
            "3389/tcp closed ms-wbt-server\n"
            "23/tcp open  telnet\n")
    assert _parse_nmap(text) == [23, 445]


def test_telnet_is_critical_with_a_reason_and_fix():
    r = assess({"192.168.1.5": [23]}, {}, "host")
    assert r.devices_exposed == 1
    f = r.findings[0]
    assert f.severity == "critical"
    assert f.source_module == "lan-exposure"
    assert "plain text" in (f.plain_message or "").lower()
    assert f.suggested_action                        # a fix is always given


def test_rdp_is_a_warning_not_critical():
    r = assess({"192.168.1.5": [3389]}, {}, "host")
    assert r.findings[0].severity == "warning"


def test_newly_opened_port_is_flagged_against_baseline():
    baseline = {"192.168.1.5": [445]}              # SMB was already open
    r = assess({"192.168.1.5": [445, 23]}, baseline, "host")
    telnet = next(f for f in r.findings if "23" in f.id)
    smb = next(f for f in r.findings if "445" in f.id)
    assert "NEWLY" in telnet.message                 # 23 is new -> called out
    assert "NEWLY" not in smb.message                # 445 was already open


def test_first_run_does_not_cry_newly():
    # empty baseline = first scan: everything is 'new' against nothing, so
    # the NEWLY tag must stay silent (same as the census first-run rule)
    r = assess({"192.168.1.1": [21, 80]}, {}, "host")
    assert all("NEWLY" not in f.message for f in r.findings)


def test_known_device_name_labels_the_finding():
    names = {"192.168.1.1": "AVM (Fritz!Box)"}
    r = assess({"192.168.1.1": [21]}, {"x": []}, "host", names=names)
    assert "[AVM (Fritz!Box)]" in r.findings[0].message


def test_clean_device_produces_no_findings():
    r = assess({"192.168.1.5": []}, {}, "host")
    assert r.findings == []
    assert r.devices_exposed == 0
    assert r.devices_scanned == 1                    # scanned, just clean


def test_acknowledged_finding_moves_to_quiet_section():
    acks = add_ack({}, "192.168.1.1", 21, "Fritz NAS")
    r = assess({"192.168.1.1": [21, 80]}, {"x": []}, "host",
               acknowledged=set(acks))
    loud = [f.id for f in r.findings]
    quiet = [f.id for f in r.accepted]
    assert ack_id("192.168.1.1", 21) in quiet       # acked -> quiet
    assert ack_id("192.168.1.1", 21) not in loud
    assert ack_id("192.168.1.1", 80) in loud        # un-acked -> still loud


def test_ack_survives_and_stays_quiet_on_rescan():
    acks = add_ack({}, "192.168.1.1", 21)
    # a later scan with the same port still muted
    r = assess({"192.168.1.1": [21]}, {"192.168.1.1": [21]}, "host",
               acknowledged=set(acks))
    assert r.findings == []                            # nothing loud
    assert len(r.accepted) == 1                        # still in the quiet list


def test_ack_store_round_trips():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "census" / "acks.json")
        acks = add_ack({}, "192.168.1.1", 21, "Fritz NAS")
        save_acks(p, acks)
        back = load_acks(p)
        assert ack_id("192.168.1.1", 21) in back
        assert back[ack_id("192.168.1.1", 21)]["note"] == "Fritz NAS"
    assert load_acks("/nonexistent/x.json") == {}      # missing -> nothing muted


def test_baseline_round_trips():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "census" / "exposure.json")
        save_exposure_baseline(p, {"192.168.1.5": [445]})
        assert load_exposure_baseline(p) == {"192.168.1.5": [445]}
    assert load_exposure_baseline("/nonexistent/x.json") == {}


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
