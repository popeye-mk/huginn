"""Tests for manual device labels (G1f) — the `label` verb.

Pins that a hand-given label: attaches to the right device (by MAC, found
via its IP), survives a re-scan (a later census must NOT overwrite it, even
when the probe returns a name), wins over the probed name everywhere it is
shown (census rows + dashboard), clears cleanly, and degrades honestly for
an IP the census never saw.

Run: python3 tools/test_label.py
"""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.census import (  # noqa: E402
    census_diff, effective_name, load_baseline, save_baseline, set_label,
)
from domains.dashboard import build_state  # noqa: E402
from engines.lan_census import Sighting  # noqa: E402
import skills.label as label_skill  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _baseline():
    return {
        "aa:bb:cc:dd:ee:01": {"ip": "192.168.1.46", "vendor": "",
                              "name": "", "first_seen": "t", "last_seen": "t"},
        "aa:bb:cc:dd:ee:02": {"ip": "192.168.1.20", "vendor": "Apple",
                              "name": "iphone", "first_seen": "t", "last_seen": "t"},
    }


# --- set_label ------------------------------------------------------------

def test_set_label_finds_device_by_ip():
    b = _baseline()
    mac = set_label(b, "192.168.1.46", "android tv box")
    check(mac == "aa:bb:cc:dd:ee:01", "should return the MAC at that IP")
    check(b[mac]["label"] == "android tv box", "label stored on the record")


def test_set_label_unknown_ip_returns_none():
    b = _baseline()
    check(set_label(b, "10.0.0.99", "nope") is None, "unknown IP -> None")
    check(all("label" not in r for r in b.values()), "nothing was labelled")


def test_empty_label_clears():
    b = _baseline()
    set_label(b, "192.168.1.46", "temp")
    mac = set_label(b, "192.168.1.46", "   ")
    check("label" not in b[mac], "blank label removes the field")


# --- precedence -----------------------------------------------------------

def test_effective_name_precedence():
    check(effective_name({"label": "L", "name": "N"}) == "L", "label wins")
    check(effective_name({"name": "N"}) == "N", "name when no label")
    check(effective_name({"vendor": "V"}) == "", "vendor is not folded in here")
    check(effective_name({}) == "", "empty -> blank")


# --- survives a re-scan ---------------------------------------------------

def test_label_survives_census_and_beats_probed_name():
    b = _baseline()
    set_label(b, "192.168.1.46", "android tv box")
    # The device answers the probe with a hostname this time.
    sightings = [Sighting(ip="192.168.1.46", mac="aa:bb:cc:dd:ee:01",
                          vendor="", name="ESP-1234")]
    res = census_diff(sightings, b, "host")
    rec = res.baseline["aa:bb:cc:dd:ee:01"]
    check(rec["label"] == "android tv box", "label is untouched by re-scan")
    check(rec["name"] == "ESP-1234", "probed name still recorded separately")
    row = next(d for d in res.devices if d["mac"] == "aa:bb:cc:dd:ee:01")
    check(row.get("label") == "android tv box", "device row carries the label")


# --- dashboard shows the label -------------------------------------------

def test_dashboard_prefers_label():
    b = _baseline()
    set_label(b, "192.168.1.20", "kitchen ipad")
    state = build_state(b, {}, machine_id="host")
    row = next(r for r in state.devices if r.mac == "aa:bb:cc:dd:ee:02")
    check(row.label == "kitchen ipad", "dashboard label prefers the manual label")


# --- the skill: parse + honest degrade + round trip ----------------------

def test_parse():
    check(label_skill._parse("192.168.1.5 my tv") == ("192.168.1.5", "my tv"),
          "ip + multiword label")
    check(label_skill._parse("192.168.1.5 clear")[1] == "", "clear -> blank")
    check(label_skill._parse("192.168.1.5")[1] == "", "ip only -> blank label")
    check(label_skill._parse("")[0] is None, "empty -> no ip")


def test_skill_usage_and_degrade(tmpdir=None):
    base = tempfile.mkdtemp()
    path = os.path.join(base, "lan_baseline.json")
    orig = label_skill._BASELINE
    label_skill._BASELINE = path
    try:
        check("Usage:" in label_skill.skill_label(""), "no args -> usage")
        check("run `census`" in label_skill.skill_label("192.168.1.9 tv").lower()
              or "census" in label_skill.skill_label("192.168.1.9 tv").lower(),
              "no baseline -> points at census")
        # Now seed a baseline and label a real device end to end.
        save_baseline(path, _baseline())
        out = label_skill.skill_label("192.168.1.46 android tv box")
        check("Labelled" in out, "labels a seen device")
        check(load_baseline(path)["aa:bb:cc:dd:ee:01"]["label"] == "android tv box",
              "label persisted to disk")
        # Unknown IP degrades honestly and changes nothing.
        out2 = label_skill.skill_label("10.0.0.5 ghost")
        check("nothing to label" in out2.lower() or "no device" in out2.lower(),
              "unknown IP -> honest no-op")
    finally:
        label_skill._BASELINE = orig


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
