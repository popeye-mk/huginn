"""Tests for host posture (H1) and the incident snapshot (H2).

H1 is the honest form of "predict before it happens": it reports standing
CONDITIONS, never attacks. These pin the parsing (injected output, no machine
touched), the wording discipline (a precondition is a warning, never critical,
and never claims something is happening), and the rule that matters most —
**a reading that failed produces no finding and is reported as unchecked**,
because the dangerous failure here is a silent "you look fine".

H2 pins that the snapshot separates "nothing seen" from "not readable", and
round-trips to disk.

Run: python3 tools/test_posture.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.incident import build_snapshot, render_summary, save_snapshot  # noqa: E402
from domains.posture import assess, unchecked  # noqa: E402
from engines.host_posture import (  # noqa: E402
    parse_firewall, parse_ipv6_ra, parse_listening, parse_llmnr, read_posture,
)

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


# --- parsing (no machine touched) -----------------------------------------

def test_parse_listening_linux_and_windows():
    ss = ("tcp   LISTEN 0 4096   0.0.0.0:445    0.0.0.0:*\n"
          "udp   UNCONN 0 0      0.0.0.0:5353   0.0.0.0:*\n")
    check(445 in parse_listening(ss), "ss LISTEN line parsed")
    win = "  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       7\n"
    check(parse_listening(win) == [3389], "windows netstat LISTENING parsed")
    check(parse_listening(None) is None, "unreadable → None, never []")


def test_parse_llmnr_including_the_windows_default():
    check(parse_llmnr("LLMNR setting: yes") is True, "explicit yes")
    check(parse_llmnr("LLMNR setting: no") is False, "explicit no")
    check(parse_llmnr("0") is False, "policy 0 → disabled")
    check(parse_llmnr("") is True,
          "EMPTY policy means Windows default ON — absence is the dangerous case")
    check(parse_llmnr(None) is None, "unreadable → None")


def test_parse_ipv6_ra_and_firewall():
    check(parse_ipv6_ra("net.ipv6.conf.all.accept_ra = 1") is True, "RA accepted")
    check(parse_ipv6_ra("net.ipv6.conf.all.accept_ra = 0") is False, "RA refused")
    check(parse_firewall("Status: active") is True, "ufw active")
    check(parse_firewall("Status: inactive") is False, "ufw inactive")
    check(parse_firewall(None) is None, "unreadable → None")


def test_read_posture_never_raises_on_a_broken_reader():
    out = read_posture(run=lambda cmd, timeout=6: (_ for _ in ()).throw(OSError()))
    check(set(out) == {"listening", "llmnr", "ipv6_ra", "firewall"}, "all four keys")
    check(all(v is None for v in out.values()), "every failed read is None")


# --- the findings: preconditions, never attacks ---------------------------

def test_llmnr_on_is_a_precondition_not_an_attack():
    f = assess({"llmnr": True}, "host")
    check(len(f) == 1 and f[0].severity == "warning",
          "a precondition is a warning, never critical")
    check("would trust" in f[0].message, "phrased as what WOULD happen")
    check("poison" not in f[0].message.lower().split("would")[0],
          "it does not claim an attack is under way")


def test_ipv6_ra_is_flagged_as_the_mitm6_precondition():
    f = assess({"ipv6_ra": True}, "host")
    check(len(f) == 1 and "mitm6" in f[0].message, "named for what it enables")


def test_our_own_risky_listening_ports_are_flagged():
    f = assess({"listening": [445, 3389, 8080]}, "host")
    ids = {x.id for x in f}
    check("posture_listening_445" in ids and "posture_listening_3389" in ids,
          "SMB and RDP on our own host are flagged")
    check("posture_listening_8080" not in ids, "a non-risky port stays quiet")


def test_safe_settings_produce_nothing():
    check(assess({"llmnr": False, "ipv6_ra": False, "firewall": True,
                  "listening": [22]}, "host") == [],
          "a hardened host has nothing to report")


def test_unknown_is_never_a_pass():
    posture = {"llmnr": None, "ipv6_ra": None, "firewall": None, "listening": None}
    check(assess(posture, "host") == [], "unknown produces no finding...")
    check(len(unchecked(posture)) == 4, "...but all four are reported unchecked")
    check(unchecked({"llmnr": True, "ipv6_ra": False, "firewall": True,
                     "listening": []}) == [], "fully-read posture has nothing unchecked")


# --- H2: the incident snapshot --------------------------------------------

def test_snapshot_separates_empty_from_unreadable():
    snap = build_snapshot("host", "2026-07-27T03:00:00+00:00",
                          {"neighbours": [], "gateway": None, "ports": [445]})
    text = render_summary(snap)
    check("nothing seen" in text, "an empty list reads as nothing seen")
    check("not readable" in text and "NOT an all-clear" in text,
          "an unreadable section is never counted as empty")
    check("1 item(s)" in text, "a populated section shows its count")


def test_snapshot_round_trips_to_disk():
    directory = os.path.join(tempfile.mkdtemp(), "incidents")
    snap = build_snapshot("host", "2026-07-27T03:04:05+00:00", {"gateway": "192.168.1.1"})
    path = save_snapshot(directory, snap)
    check(os.path.exists(path) and "incident-" in os.path.basename(path),
          "written under a timestamped name")
    with open(path, encoding="utf-8") as fh:
        back = json.load(fh)
    check(back["sections"]["gateway"] == "192.168.1.1", "content survives the trip")
    check(back["captured_at"] == "2026-07-27T03:04:05+00:00", "the moment is recorded")


# --- H2: collect() — the shape mapping that live use actually exercises ----

def test_collect_maps_neighbours_from_sighting_objects():
    """The bug that shipped: raw_pairs returns Sighting OBJECTS, not tuples.

    `capture` failed in live use with "cannot unpack non-iterable Sighting
    object" — and no test caught it, because the patrol test stubbed
    take_snapshot and this file only tested the pure snapshot builders.
    collect() was the one function with real consumers and no coverage. It is
    covered now, by injection: no host is read here either.
    """
    import agents.capturing as capturing
    from engines.lan_census import Sighting

    class _Engine:
        def is_available(self):
            return True

        def run(self):
            class _Out:
                payload = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE"
            return _Out()

    saved = (capturing.LanCensusEngine, capturing.raw_pairs, capturing.read_gateway,
             capturing.read_dhcp_server, capturing.local_networks, capturing.read_posture,
             capturing.summarize)
    capturing.LanCensusEngine = _Engine
    capturing.raw_pairs = lambda text: [
        Sighting(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:01", vendor="AVM"),
        Sighting(ip="192.168.1.5", mac="aa:bb:cc:dd:ee:02", vendor=""),
    ]
    capturing.read_gateway = lambda: "192.168.1.1"
    capturing.read_dhcp_server = lambda: "192.168.1.1"
    capturing.local_networks = lambda: ["192.168.1.0/24"]
    capturing.read_posture = lambda: {"listening": [445], "llmnr": True,
                                      "ipv6_ra": False, "firewall": True}
    capturing.summarize = lambda *a, **k: None
    try:
        out = capturing.collect()
        check(out["neighbours"] == [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:01", "vendor": "AVM"},
            {"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:02", "vendor": ""},
        ], "Sighting objects map to plain dicts — the fix for the live crash")
        check(out["gateway"] == "192.168.1.1", "gateway carried")
        check(out["listening_ports"] == [445], "own ports carried from posture")
        check(out["llmnr_answers"] is True, "posture flags carried")
    finally:
        (capturing.LanCensusEngine, capturing.raw_pairs, capturing.read_gateway,
         capturing.read_dhcp_server, capturing.local_networks,
         capturing.read_posture, capturing.summarize) = saved


def test_collect_reports_unreadable_as_none_not_empty():
    """An engine that cannot run must leave None, so the summary can say
    'not readable' rather than the far more dangerous 'nothing seen'."""
    import agents.capturing as capturing

    class _Dead:
        def is_available(self):
            return False

    saved = (capturing.LanCensusEngine, capturing.read_gateway,
             capturing.read_posture, capturing.summarize)
    capturing.LanCensusEngine = _Dead
    capturing.read_gateway = lambda: (_ for _ in ()).throw(OSError("no tool"))
    capturing.read_posture = lambda: {}
    capturing.summarize = lambda *a, **k: None
    try:
        out = capturing.collect()
        check(out["neighbours"] is None, "an unavailable engine leaves None, not []")
        check(out["gateway"] is None, "a raising reader leaves None")
    finally:
        (capturing.LanCensusEngine, capturing.read_gateway,
         capturing.read_posture, capturing.summarize) = saved


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
