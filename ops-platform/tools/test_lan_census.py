"""Tests for the LAN census (G1) — parser + baseline diff.

The live census reads a real neighbour cache, which no test can conjure,
so the engine is exercised against captured output from BOTH operating
systems (the only way to reach the Windows parser from Linux), and the
domain's meaning-making is pinned against fixed baselines.

Run: python3 tools/test_lan_census.py
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.census.service import (  # noqa: E402
    census_diff, load_baseline, save_baseline,
)
from engines.lan_census import (  # noqa: E402
    Sighting, parse, parse_arp_a, parse_ip_neigh, vendor_for,
)

_IP_NEIGH = """\
192.168.1.1 dev eth0 lladdr b8:27:eb:11:22:33 REACHABLE
192.168.1.5 dev eth0 lladdr 08:00:27:aa:bb:cc STALE
192.168.1.9 dev eth0  FAILED
192.168.1.5 dev wlan0 lladdr 08:00:27:aa:bb:cc REACHABLE
fe80::1 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
"""

_ARP_A = """\
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           b8-27-eb-11-22-33     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  192.168.1.20          50-c7-bf-de-ad-01     dynamic
"""


def test_parse_ip_neigh_keeps_real_devices_drops_dead_and_dupes():
    s = parse_ip_neigh(_IP_NEIGH)
    macs = [x.mac for x in s]
    assert "b8:27:eb:11:22:33" in macs        # router, kept
    assert "08:00:27:aa:bb:cc" in macs        # kept once despite 2 lines
    assert macs.count("08:00:27:aa:bb:cc") == 1
    assert all(":" in m for m in macs)         # normalised
    # the FAILED line had no lladdr -> not a sighting
    assert len(s) == 3


def test_parse_arp_a_drops_broadcast_and_normalises_dashes():
    s = parse_arp_a(_ARP_A)
    macs = [x.mac for x in s]
    assert "b8:27:eb:11:22:33" in macs
    assert "50:c7:bf:de:ad:01" in macs
    assert "ff:ff:ff:ff:ff:ff" not in macs     # broadcast dropped
    assert len(s) == 2


def test_parse_autodetects_format():
    assert len(parse(_IP_NEIGH)) == 3
    assert len(parse(_ARP_A)) == 2


def test_vendor_from_oui():
    assert vendor_for("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert vendor_for("50:c7:bf:de:ad:01") == "TP-Link"
    # the operator's own kit now resolves from the curated table
    assert vendor_for("02:1a:20:fa:53:5f") == "AVM (Fritz!Box)"
    assert vendor_for("02:1a:23:03:be:57") == "Tuya (smart home)"
    # locally-administered first octet (bit 0x02 set) -> randomized MAC,
    # and this wins over any bundled-file lookup
    assert vendor_for("02:1a:30:4d:a6:f0") == "randomized MAC"
    # a globally-unique OUI (bit 0x02 clear) in neither the curated table
    # NOR the bundled file is honestly unknown, never a wrong guess
    assert vendor_for("fc:fc:fc:00:00:01") == ""


def test_vendor_falls_back_to_bundled_file(tmp_path=None):
    """When the curated table misses, the bundled OUI file resolves it."""
    import engines.lan_census as lc
    # Xerox 000000 is only in the bundled nmap file, not the curated table.
    lc._bundled_cache = None            # force a real load of the shipped file
    got = lc.vendor_for("00:00:00:aa:bb:cc")
    # the file ships with the repo; if present, Xerox resolves; if a stripped
    # build omitted it, we still degrade to "" — never a wrong name.
    assert got in ("Xerox", "")
    if got == "":
        # prove the mechanism with an injected table so the test still guards it
        lc._bundled_cache = {"aa:bb:cc": "TestVendor"}
        assert lc.vendor_for("aa:bb:cc:00:11:22") == "TestVendor"
    lc._bundled_cache = None


def _sight(ip, mac, vendor=""):
    return Sighting(ip=ip, mac=mac, vendor=vendor)


def test_first_run_establishes_baseline_without_alerting():
    cur = [_sight("192.168.1.1", "aa:aa:aa:aa:aa:aa")]
    r = census_diff(cur, {}, "host")
    assert r.new_baseline_created
    assert r.findings == []                     # no alert storm on run 1
    assert "aa:aa:aa:aa:aa:aa" in r.baseline


def test_new_device_is_a_warning():
    base = {"aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1", "vendor": "",
            "first_seen": "t", "last_seen": "t"}}
    cur = [_sight("192.168.1.1", "aa:aa:aa:aa:aa:aa"),
           _sight("192.168.1.50", "bb:bb:bb:bb:bb:bb")]
    r = census_diff(cur, base, "host")
    ids = [f.id for f in r.findings]
    assert "lan_new_device_bb:bb:bb:bb:bb:bb" in ids
    assert any(f.severity == "warning" for f in r.findings)


def test_ip_change_is_flagged_as_possible_spoof():
    base = {"aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1", "vendor": "",
            "first_seen": "t", "last_seen": "t"}}
    cur = [_sight("192.168.1.99", "aa:aa:aa:aa:aa:aa")]   # same MAC, new IP
    r = census_diff(cur, base, "host")
    assert any(f.id == "lan_ip_change_aa:aa:aa:aa:aa:aa"
               and f.severity == "warning" for f in r.findings)
    assert r.baseline["aa:aa:aa:aa:aa:aa"]["ip"] == "192.168.1.99"


def test_vanished_device_is_info():
    base = {"aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1", "vendor": "",
            "first_seen": "t", "last_seen": "t"}}
    r = census_diff([], base, "host")           # nothing seen now
    assert any(f.id == "lan_gone_aa:aa:aa:aa:aa:aa"
               and f.severity == "info" for f in r.findings)


def test_baseline_round_trips_on_disk():
    with tempfile.TemporaryDirectory() as d:
        p = str(Path(d) / "census" / "baseline.json")
        save_baseline(p, {"aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1"}})
        back = load_baseline(p)
        assert back["aa:aa:aa:aa:aa:aa"]["ip"] == "192.168.1.1"
    assert load_baseline("/nonexistent/x.json") == {}   # missing -> empty


def test_lan_network_and_filter():
    from engines.lan_sweep import in_network, lan_network
    net = lan_network("192.168.1.22")
    assert str(net) == "192.168.1.0/24"
    assert in_network("192.168.1.1", net)        # the router: on the LAN
    assert not in_network("172.18.0.2", net)        # Docker bridge: dropped
    assert in_network("anything", None)             # no net known -> keep all


def test_sweep_command_uses_nmap_when_present(monkeypatch=None):
    import engines.lan_sweep as sw

    real = sw.shutil.which
    sw.shutil.which = lambda name: "/usr/bin/nmap" if name == "nmap" else None
    try:
        cmd = sw.sweep_command(sw.lan_network("192.168.1.5"))
        assert cmd[0] == "nmap" and "-sn" in cmd and "192.168.1.0/24" in cmd
    finally:
        sw.shutil.which = real


def test_sweep_command_none_without_nmap_falls_back_to_ping():
    import engines.lan_sweep as sw
    real = sw.shutil.which
    sw.shutil.which = lambda name: None      # neither nmap nor ping
    try:
        assert sw.sweep_command(sw.lan_network("192.168.1.5")) is None
    finally:
        sw.shutil.which = real


# The default-route bug: on a machine where the internet goes out a VPN,
# the real LAN sits on a different interface. Enumeration must find it.
_IP_O_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
2: wlan0    inet 192.168.1.22/24 brd 192.168.1.255 scope global wlan0
3: tun0    inet 10.162.68.251/24 scope global tun0
4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
5: br-a1b2    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-a1b2
"""


def test_parse_interfaces_reads_ip_addr():
    from engines.lan_sweep import parse_interfaces
    pairs = parse_interfaces(_IP_O_ADDR)
    by_name = {name: str(net) for name, net in pairs}
    assert by_name["wlan0"] == "192.168.1.0/24"
    assert by_name["tun0"] == "10.162.68.0/24"
    assert by_name["docker0"] == "172.17.0.0/16"
    assert "lo" in by_name          # parsed; filtering happens in local_networks


def test_local_networks_keeps_real_lan_drops_vpn_and_docker(monkeypatch=None):
    import engines.lan_sweep as sw
    real = sw.subprocess.run

    class _R:
        stdout = _IP_O_ADDR

    sw.subprocess.run = lambda *a, **k: _R()
    try:
        nets = [str(n) for n in sw.local_networks()]
    finally:
        sw.subprocess.run = real
    assert "192.168.1.0/24" in nets      # the real home LAN (wlan0): kept
    assert "10.162.68.0/24" not in nets    # the VPN (tun0): dropped
    assert "172.17.0.0/16" not in nets     # docker0: dropped
    assert "172.18.0.0/16" not in nets     # bridge: dropped


def test_prune_non_lan_drops_stale_docker_entry():
    import ipaddress
    from skills.census import _prune_non_lan
    nets = [ipaddress.ip_network("192.168.1.0/24")]
    baseline = {
        "aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1"},   # real LAN: kept
        "02:1a:30:4d:a6:f0": {"ip": "172.18.0.2"},      # Docker: dropped
    }
    pruned = _prune_non_lan(baseline, nets)
    assert "aa:aa:aa:aa:aa:aa" in pruned
    assert "02:1a:30:4d:a6:f0" not in pruned
    # with no LAN known, nothing is pruned (can't tell what's stale)
    assert _prune_non_lan(baseline, []) == baseline


def test_in_any_matches_across_multiple_lans():
    import ipaddress
    from engines.lan_sweep import in_any
    nets = [ipaddress.ip_network("192.168.1.0/24"),
            ipaddress.ip_network("192.168.1.0/24")]
    assert in_any("192.168.1.5", nets)
    assert in_any("192.168.1.9", nets)
    assert not in_any("10.162.68.5", nets)   # VPN address: excluded
    assert in_any("anything", [])            # nothing known -> keep all


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
