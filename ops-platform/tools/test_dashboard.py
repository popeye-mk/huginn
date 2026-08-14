"""Tests for the dashboard domain (G5) — state assembly, read-only.

The dashboard computes nothing new; it folds the two baselines into one
view. These pin the folding: devices carry their names, open ports set the
heat colour, the hottest device sorts first, and an empty baseline yields
an empty (not falsely-clean) state.

Run: python3 tools/test_dashboard.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.dashboard import build_state, classify_device  # noqa: E402

_CENSUS = {
    "aa:aa:aa:aa:aa:aa": {"ip": "192.168.1.1", "name": "AVM (Fritz!Box)",
                          "vendor": "AVM", "first_seen": "t0", "last_seen": "t9"},
    "bb:bb:bb:bb:bb:bb": {"ip": "192.168.1.50", "name": "",
                          "vendor": "Tuya", "first_seen": "t1", "last_seen": "t9"},
    "cc:cc:cc:cc:cc:cc": {"ip": "192.168.1.9", "name": "printer",
                          "vendor": "HP", "first_seen": "t2", "last_seen": "t9"},
}
_EXPO = {
    "192.168.1.1": [80],          # HTTP admin -> warning
    "192.168.1.50": [23],         # telnet -> critical
    "192.168.1.9": [],            # nothing -> clear
}


def test_devices_carry_name_and_ports():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    by_ip = {d.ip: d for d in st.devices}
    assert by_ip["192.168.1.1"].label == "AVM (Fritz!Box)"
    assert by_ip["192.168.1.50"].label == "Tuya"   # falls back to vendor
    assert by_ip["192.168.1.50"].open_ports == [23]


def test_heat_reflects_port_severity():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    by_ip = {d.ip: d for d in st.devices}
    assert by_ip["192.168.1.50"].heat == "critical"   # telnet
    assert by_ip["192.168.1.1"].heat == "warning"     # http admin
    assert by_ip["192.168.1.9"].heat == "clear"       # nothing open


def test_hottest_device_sorts_first():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    assert st.devices[0].heat == "critical"             # telnet box on top


def test_counts_are_right():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    assert st.device_count == 3
    assert st.exposed_count == 2                         # .1 and .50
    assert st.critical_count == 1                        # only .50


def test_empty_baseline_is_empty_not_clean():
    st = build_state({}, {}, machine_id="host")
    assert st.device_count == 0
    assert st.as_dict()["devices"] == []


def test_as_dict_is_json_shaped():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    d = st.as_dict()
    assert set(d) >= {"generated_at", "machine_id", "device_count", "devices"}
    assert "port_names" in d["devices"][0]              # for the view
    assert "device_type" in d["devices"][0]             # G9 fingerprint


# --- G9: device fingerprinting -------------------------------------------

def test_classify_by_vendor_and_name():
    assert classify_device("AVM", "AVM (Fritz!Box)", []) == "router"
    assert classify_device("Tuya", "", []) == "IoT / smart-home"
    assert classify_device("HP", "printer", []) == "printer"
    assert classify_device("Apple", "Alex-iPhone", []) == "phone / tablet"
    assert classify_device("", "", []) == "unknown"


def test_classify_by_open_ports():
    assert classify_device("Unknown", "", [9100]) == "printer"       # JetDirect
    assert classify_device("Unknown", "host", [445]) == "computer"   # SMB
    assert classify_device("Unknown", "box", [5000]) == "NAS"


def test_randomized_mac_is_a_phone():
    assert classify_device("randomized MAC", "", []) == "phone / tablet"


def test_printer_wins_over_a_generic_vendor():
    # A printer with SMB open (445) is still a printer, not a computer.
    assert classify_device("Brother", "office-laserjet", [445, 9100]) == "printer"


def test_device_row_exposes_the_type():
    st = build_state(_CENSUS, _EXPO, machine_id="host")
    by_ip = {d.ip: d for d in st.devices}
    assert by_ip["192.168.1.1"].device_type == "router"      # Fritz!Box
    assert by_ip["192.168.1.9"].device_type == "printer"     # name "printer"


# --- G10: the G7 timeline folded into the dashboard -----------------------

def test_recent_changes_are_carried_into_the_state():
    changes = [{"severity": "warning", "message": "New device .46", "last": "t", "count": 1}]
    st = build_state(_CENSUS, _EXPO, machine_id="host", recent_changes=changes)
    assert st.as_dict()["recent_changes"] == changes, "changes ride in the JSON payload"
    assert build_state({}, {}).as_dict()["recent_changes"] == [], "default is empty, not missing"


def test_changes_section_renders_and_is_honest_when_empty():
    import skills.dashboard as dash
    from domains.timeline import Change, TimelineSummary

    live = TimelineSummary(
        changes=[Change("lan_new_x", "critical", "New device on the LAN: .46",
                        "2026-07-24T10:00:00", "2026-07-24T13:00:00", 3)],
        since_days=7, total_events=3, has_history=True)
    html_out = dash._changes_html(live)
    assert "New device on the LAN: .46" in html_out, "the change is shown"
    assert "3×" in html_out and "crit" in html_out, "count + severity styling"

    no_hist = TimelineSummary(since_days=7, has_history=False)
    assert "hasn't" not in dash._changes_html(no_hist).lower()  # not phrased that way
    assert "No guard history yet" in dash._changes_html(no_hist), "no journal → honest, not all-clear"

    quiet = TimelineSummary(changes=[], since_days=7, has_history=True)
    assert "No changes on the LAN" in dash._changes_html(quiet), "quiet window stated plainly"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
