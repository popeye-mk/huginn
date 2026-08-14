"""Tests for LAN name resolution (G1e).

Live DNS/mDNS/NetBIOS can't run in a test, so the network primitives are
monkeypatched and the logic around them is pinned: the source order, the
first-real-answer rule, the honest blank when nothing answers, and the
suffix cleaning that turns `host.local.` into `host`.

Run: python3 tools/test_lan_names.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import engines.lan_names as ln  # noqa: E402
from engines.lan_census import Sighting  # noqa: E402


def test_clean_strips_dot_and_local_suffix():
    assert ln._clean("host.local.") == "host"
    assert ln._clean("printer.fritz.box") == "printer"
    assert ln._clean("nas.lan") == "nas"
    assert ln._clean("plainname") == "plainname"
    assert ln._clean("") == ""


def test_resolve_prefers_ptr_then_stops():
    ln_ptr = ln.name_via_ptr
    ln_av = ln.name_via_avahi
    ln.name_via_ptr = lambda ip: "alex-laptop"
    ln.name_via_avahi = lambda ip: "should-not-be-used"
    try:
        assert ln.resolve_name("192.168.1.5") == "alex-laptop"
    finally:
        ln.name_via_ptr, ln.name_via_avahi = ln_ptr, ln_av


def test_resolve_falls_through_to_next_source():
    ln_ptr, ln_av, ln_nb = ln.name_via_ptr, ln.name_via_avahi, ln.name_via_netbios
    ln.name_via_ptr = lambda ip: ""          # PTR silent
    ln.name_via_avahi = lambda ip: ""        # mDNS silent
    ln.name_via_netbios = lambda ip: "WINBOX"  # NetBIOS answers
    try:
        assert ln.resolve_name("192.168.1.9") == "WINBOX"
    finally:
        ln.name_via_ptr, ln.name_via_avahi, ln.name_via_netbios = ln_ptr, ln_av, ln_nb


def test_resolve_returns_blank_when_all_silent():
    ln_ptr, ln_av, ln_nb = ln.name_via_ptr, ln.name_via_avahi, ln.name_via_netbios
    ln.name_via_ptr = ln.name_via_avahi = ln.name_via_netbios = lambda ip: ""
    try:
        assert ln.resolve_name("192.168.1.71") == ""   # randomized phone
    finally:
        ln.name_via_ptr, ln.name_via_avahi, ln.name_via_netbios = ln_ptr, ln_av, ln_nb


def test_ptr_returns_blank_on_failure():
    real = ln.socket.gethostbyaddr
    ln.socket.gethostbyaddr = lambda ip: (_ for _ in ()).throw(OSError("NXDOMAIN"))
    try:
        assert ln.name_via_ptr("10.0.0.1") == ""
    finally:
        ln.socket.gethostbyaddr = real


def test_avahi_and_netbios_skip_cleanly_when_tool_absent():
    real = ln.shutil.which
    ln.shutil.which = lambda name: None       # neither tool installed
    try:
        assert ln.name_via_avahi("192.168.1.5") == ""
        assert ln.name_via_netbios("192.168.1.5") == ""
    finally:
        ln.shutil.which = real


def test_sighting_carries_name_immutably():
    s = Sighting(ip="192.168.1.5", mac="aa:bb:cc:dd:ee:ff", vendor="Apple")
    named = s.with_name("alex-iphone")
    assert named.name == "alex-iphone"
    assert s.name == ""                       # original unchanged (frozen)
    assert named.as_dict()["name"] == "alex-iphone"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
