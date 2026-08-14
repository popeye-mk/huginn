"""Tests for the LAN anomaly watch (G3) — ARP-spoof + rogue-DHCP.

The detectors run on data a live host holds, which a test can't conjure,
so each is exercised against constructed sightings and captured OS text.
The point of every test is a claim about *meaning*: a duplicate is a spoof
signal, a non-gateway lease server is a rogue-DHCP signal, and normal
multi-homing / a gateway-issued lease stay quiet.

Run: python3 tools/test_lan_anomaly.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.anomaly import (  # noqa: E402
    detect_arp_flood, detect_arp_spoof, detect_mac_flood, detect_rogue_dhcp,
)
from contracts.finding import Coverage, Finding  # noqa: E402
from engines.lan_anomaly import parse_dhcp_server, parse_gateway  # noqa: E402
from engines.lan_census import Sighting, raw_pairs  # noqa: E402


def _s(ip, mac):
    return Sighting(ip=ip, mac=mac, vendor="")


# --- ARP spoof -----------------------------------------------------------

def test_duplicate_ip_two_macs_is_flagged():
    # one IP (the gateway) claimed by two MACs = classic impersonation
    pairs = [_s("192.168.1.1", "aa:aa:aa:aa:aa:aa"),
             _s("192.168.1.1", "bb:bb:bb:bb:bb:bb"),
             _s("192.168.1.5", "cc:cc:cc:cc:cc:cc")]
    findings = detect_arp_spoof(pairs, "host")
    ids = [f.id for f in findings]
    assert "arp_dup_ip_192.168.1.1" in ids
    dup = next(f for f in findings if f.id == "arp_dup_ip_192.168.1.1")
    assert dup.severity == "warning"
    assert "aa:aa:aa:aa:aa:aa" in dup.message and "bb:bb:bb:bb:bb:bb" in dup.message


def test_one_mac_many_ips_is_flagged():
    # one MAC answering for many addresses = a middle-man sweep
    attacker = "de:ad:be:ef:00:01"
    pairs = [_s(f"192.168.1.{n}", attacker) for n in (10, 11, 12, 13)]
    findings = detect_arp_spoof(pairs, "host")
    assert any(f.id == f"arp_many_ips_{attacker}" and f.severity == "warning"
               for f in findings)


def test_gateway_is_exempt_from_promiscuous_check():
    # the router legitimately answers ARP for many IPs -> must NOT be flagged
    gw = "02:1a:20:fa:53:5f"
    pairs = [_s(f"192.168.1.{n}", gw) for n in (1, 5, 10, 20)]
    # with the gateway IP passed, the router's many-IPs is normal
    assert detect_arp_spoof(pairs, "host", gateway_ip="192.168.1.1") == []
    # without knowing the gateway, it still fires (can't tell it's the router)
    assert detect_arp_spoof(pairs, "host") != []


def test_gateway_impersonation_still_caught():
    # even exempt from promiscuous, a SECOND MAC claiming the gateway IP
    # is the duplicate-IP signal — the most important catch of all
    gw = "02:1a:20:fa:53:5f"
    attacker = "de:ad:be:ef:00:01"
    pairs = [_s("192.168.1.1", gw),
             _s("192.168.1.1", attacker)]   # attacker claims gateway IP
    findings = detect_arp_spoof(pairs, "host", gateway_ip="192.168.1.1")
    assert any(f.id == "arp_dup_ip_192.168.1.1" for f in findings)


def test_normal_cache_is_quiet():
    # every device one IP, every IP one MAC -> nothing
    pairs = [_s("192.168.1.1", "aa:aa:aa:aa:aa:aa"),
             _s("192.168.1.5", "bb:bb:bb:bb:bb:bb"),
             _s("192.168.1.9", "cc:cc:cc:cc:cc:cc")]
    assert detect_arp_spoof(pairs, "host") == []


def test_mac_with_two_ips_stays_quiet_below_threshold():
    # a dual-homed box on 2 IPs is normal; only >= 3 trips the promiscuous check
    pairs = [_s("192.168.1.5", "aa:aa:aa:aa:aa:aa"),
             _s("192.168.1.6", "aa:aa:aa:aa:aa:aa")]
    assert detect_arp_spoof(pairs, "host") == []


def test_raw_pairs_preserves_the_duplicate_census_would_hide():
    text = ("192.168.1.1 dev wlan0 lladdr aa:aa:aa:aa:aa:aa REACHABLE\n"
            "192.168.1.1 dev wlan0 lladdr bb:bb:bb:bb:bb:bb STALE\n")
    pairs = raw_pairs(text)
    assert len(pairs) == 2                     # both kept — the spoof survives
    assert {p.mac for p in pairs} == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}


# --- rogue DHCP ----------------------------------------------------------

def test_rogue_dhcp_flagged_when_server_is_not_gateway():
    findings = detect_rogue_dhcp("192.168.1.99", "192.168.1.1", "host")
    assert len(findings) == 1
    assert findings[0].id == "rogue_dhcp_192.168.1.99"
    assert findings[0].severity == "warning"


def test_no_rogue_when_gateway_issued_the_lease():
    assert detect_rogue_dhcp("192.168.1.1", "192.168.1.1", "host") == []


def test_no_rogue_finding_when_a_signal_is_unknown():
    # unknown DHCP server or gateway -> can't judge -> no false alarm
    assert detect_rogue_dhcp(None, "192.168.1.1", "host") == []
    assert detect_rogue_dhcp("192.168.1.99", None, "host") == []


# --- engine parsers ------------------------------------------------------

def test_parse_gateway_linux():
    text = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
    assert parse_gateway(text) == "192.168.1.1"


def test_parse_gateway_windows_bare_nexthop():
    assert parse_gateway("192.168.1.1\n") == "192.168.1.1"


def test_parse_gateway_none_when_absent():
    assert parse_gateway("") is None


def test_parse_dhcp_server_from_nmcli():
    text = ("IP4.ADDRESS[1]:192.168.1.22/24\n"
            "DHCP4.OPTION[6]:dhcp_server_identifier = 192.168.1.1\n")
    assert parse_dhcp_server(text) == "192.168.1.1"


def test_parse_dhcp_server_none_when_absent():
    assert parse_dhcp_server("no dhcp info here") is None


# --- G13: flood detection by symptom --------------------------------------

def _census_finding(fid):
    """A census finding as census_diff emits them (id prefix is the signal)."""
    return Finding(
        id=fid, source_module="lan-census", machine_id="host",
        severity="warning", confidence="certain", message=fid,
        coverage=Coverage(checked=1, total=1), tags=("security", "lan"),
    )


def test_mass_address_churn_reads_as_an_arp_flood():
    findings = [_census_finding(f"lan_ip_change_{i}") for i in range(6)]
    out = detect_arp_flood(findings, "host", seen=20)
    assert len(out) == 1, "6 changes (>= 5) → flagged"
    assert "gratuitous-ARP flood" in out[0].message
    assert out[0].confidence == "likely", "a symptom is likely, never certain"
    assert "not captured" in (out[0].suggested_action or ""), "says the packets weren't seen"


def test_ordinary_dhcp_churn_stays_quiet():
    findings = [_census_finding(f"lan_ip_change_{i}") for i in range(2)]
    assert detect_arp_flood(findings, "host", seen=20) == [], "2 changes → normal, quiet"
    assert detect_arp_flood([], "host") == [], "no changes → quiet"


def test_a_burst_of_new_macs_reads_as_dhcp_starvation():
    findings = [_census_finding(f"lan_new_device_{i}") for i in range(12)]
    out = detect_mac_flood(findings, "host", seen=30)
    assert len(out) == 1, "12 new MACs (>= 10) → flagged"
    assert "DHCP starvation" in out[0].message
    assert out[0].coverage.checked == 12, "coverage names how many it counted"


def test_a_few_new_devices_stay_quiet():
    findings = [_census_finding(f"lan_new_device_{i}") for i in range(3)]
    assert detect_mac_flood(findings, "host", seen=20) == [], "3 new devices → normal"


def test_the_two_flood_detectors_do_not_cross_fire():
    changes = [_census_finding(f"lan_ip_change_{i}") for i in range(8)]
    assert detect_mac_flood(changes, "host") == [], "churn is not a MAC flood"
    fresh = [_census_finding(f"lan_new_device_{i}") for i in range(12)]
    assert detect_arp_flood(fresh, "host") == [], "new devices are not ARP churn"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
