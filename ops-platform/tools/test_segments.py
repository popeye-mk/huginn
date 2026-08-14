"""Tests for segment awareness — hosts on different networks (chapter 2, item 5).

Split from test_corroboration.py at the 400-line hard limit.

Every test here exists because of one live discovery: the operator's Windows
box reported 192.168.122.58 with gateway 192.168.122.1 — libvirt's default
NAT range — while the laptop sat on 192.168.1.0/24 behind the Fritz!Box.
Two different networks, two different gateway MACs, and the first version of
this code compared them anyway. It would have raised a CRITICAL "ARP
spoofing" alert manufactured entirely out of ordinary topology.

A corroboration tool that invents attacks from a VM's NAT interface is worse
than no corroboration at all: it teaches the operator to disbelieve it.

Run: python3 tools/test_segments.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.observation import Observation  # noqa: E402
from domains.corroboration import (  # noqa: E402
    assess, gateway_disagreement, segments, verdict,
)

passed = 0
NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def obs(machine, gw_mac="aa:bb:cc:dd:ee:01", minutes_ago=1,
        neighbours=None, readable=True, gw_ip="192.168.1.1"):
    return Observation(
        machine_id=machine,
        observed_at=(NOW - timedelta(minutes=minutes_ago)).isoformat(),
        gateway_ip=gw_ip,
        gateway_mac=gw_mac,
        neighbours=neighbours if neighbours is not None else {"192.168.1.5": "11:22:33:44:55:66"},
        readable=readable,
    )


def test_segments_groups_by_gateway_ip():
    grouped = segments([obs("a", gw_ip="10.0.0.1"), obs("b", gw_ip="10.0.0.1"),
                        obs("c", gw_ip="172.16.0.1")])
    check(set(grouped) == {"10.0.0.1", "172.16.0.1"}, "two segments")
    check(len(grouped["10.0.0.1"]) == 2, "two hosts share the first")


def test_a_host_with_no_gateway_belongs_to_no_segment():
    """It cannot be placed, so it cannot corroborate anyone."""
    check(segments([obs("a", gw_ip=None)]) == {},
          "no gateway means no segment membership")




def test_hosts_on_DIFFERENT_subnets_never_produce_a_conflict():
    """The false positive that live use nearly produced.

    The operator's Windows box turned out to be on 192.168.122.0/24
    (libvirt's default NAT range) while the laptop was on 192.168.1.0/24.
    Two different gateways, two different MACs, and the first version of this
    code compared them anyway -- manufacturing a CRITICAL "ARP spoofing"
    alert out of ordinary network topology.

    Corroboration only means anything within one segment.
    """
    laptop = obs("laptop", "aa:bb:cc:dd:ee:01", gw_ip="192.168.1.1")
    winbox = obs("winbox", "de:ad:be:ef:00:99", gw_ip="192.168.122.1")
    check(gateway_disagreement([laptop, winbox], "laptop") == [],
          "different gateways are different networks, not a disagreement")
    check(assess([laptop, winbox], "laptop", NOW) == [] or
          all(f.severity == "info" for f in assess([laptop, winbox], "laptop", NOW)),
          "and nothing critical is raised")


def test_the_verdict_says_the_hosts_are_split_across_segments():
    """Two witnesses to two different networks corroborate nothing, and the
    operator has to be told WHY rather than left reading 'can_corroborate:
    false' next to two host names."""
    laptop = obs("laptop", gw_ip="192.168.1.1")
    winbox = obs("winbox", gw_ip="192.168.122.1")
    state = verdict([laptop, winbox], NOW)
    check(state["host_count"] == 2, "both hosts are present")
    check(state["can_corroborate"] is False,
          "but they cannot corroborate: different segments")
    check(state["split_across_segments"] is True, "and that is stated")
    check(set(state["segments"]) == {"192.168.1.1", "192.168.122.1"},
          "with each segment and its witnesses named")


def test_two_hosts_on_the_SAME_segment_still_corroborate():
    """The fix must not disable the feature it protects."""
    laptop = obs("laptop", "aa:bb:cc:dd:ee:01", gw_ip="192.168.1.1")
    winbox = obs("winbox", "aa:bb:cc:dd:ee:01", gw_ip="192.168.1.1")
    state = verdict([laptop, winbox], NOW)
    check(state["can_corroborate"] is True, "same gateway -> corroboration works")
    check(state["split_across_segments"] is False, "and they are not split")
    spoofed = obs("winbox", "de:ad:be:ef:00:99", gw_ip="192.168.1.1")
    found = gateway_disagreement([laptop, spoofed], "laptop")
    check(len(found) == 1 and found[0].severity == "critical",
          "and a real conflict on that segment is still critical")


def test_a_third_host_on_its_own_segment_does_not_break_the_pair():
    """One machine on a VM network must not suppress a real conflict between
    two machines that DO share the physical LAN."""
    a = obs("laptop", "aa:bb:cc:dd:ee:01", gw_ip="192.168.1.1")
    b = obs("desktop", "de:ad:be:ef:00:99", gw_ip="192.168.1.1")
    vm = obs("winvm", "11:22:33:44:55:66", gw_ip="192.168.122.1")
    found = gateway_disagreement([a, b, vm], "laptop")
    check(len(found) == 1, "exactly one conflict, on the shared segment")
    check("192.168.1.1" in found[0].message, "and it names the right gateway")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
