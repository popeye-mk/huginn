"""Linux battery and Wi-Fi collectors (spec §4.2).

Both bugs covered here were found by running on a real laptop and
inspecting the *values*, not by reading the report. The report looked
correct in both cases — which is the point. A collector that returns
null for its key metric produces no finding, and no finding renders as
"nothing wrong". Only looking at the data distinguished "the battery is
healthy" from "health was never calculated".

sysfs is simulated on disk here so the failure is reproducible without
the specific laptop that exposed it.
"""

import json

import pytest

from collectors.base import Skip
from collectors.optional import battery, wifi


# --- battery ----------------------------------------------------------

def _make_battery(tmp_path, name="BAT1", **files):
    bat = tmp_path / "power_supply" / name
    bat.mkdir(parents=True)
    for key, value in files.items():
        (bat / key).write_text(str(value), encoding="utf-8")
    return bat


def test_health_from_watt_hour_firmware(tmp_path):
    bat = _make_battery(tmp_path, capacity=80, status="Discharging",
                        energy_full=45000000, energy_full_design=50000000)
    health, unit, unavailable = battery._battery_health(str(bat))
    assert health == 90.0
    assert unit == "Wh"
    assert unavailable is None


def test_health_from_amp_hour_firmware(tmp_path):
    """The regression: an Acer reporting charge_* returned null health.

    Both rules that read min_health_percent were structurally unfireable
    on that hardware, and nothing in the report said so.
    """
    bat = _make_battery(tmp_path, capacity=97, status="Discharging",
                        charge_full=3000000, charge_full_design=4000000)
    health, unit, unavailable = battery._battery_health(str(bat))
    assert health == 75.0
    assert unit == "Ah"
    assert unavailable is None


def test_watt_hours_preferred_when_firmware_reports_both(tmp_path):
    bat = _make_battery(tmp_path, energy_full=45000000, energy_full_design=50000000,
                        charge_full=1000000, charge_full_design=4000000)
    health, unit, _ = battery._battery_health(str(bat))
    assert (health, unit) == (90.0, "Wh")


def test_missing_capacity_files_explain_themselves(tmp_path):
    """A bare null leaves a reader guessing whether it means healthy."""
    bat = _make_battery(tmp_path, capacity=50, status="Full")
    health, _unit, unavailable = battery._battery_health(str(bat))
    assert health is None
    assert unavailable and "neither" in unavailable


def test_zero_design_capacity_does_not_crash_or_invent(tmp_path):
    bat = _make_battery(tmp_path, charge_full=3000000, charge_full_design=0)
    health, _unit, unavailable = battery._battery_health(str(bat))
    assert health is None
    assert unavailable


def test_unparseable_values_are_treated_as_absent(tmp_path):
    bat = _make_battery(tmp_path, energy_full="unknown", energy_full_design="unknown")
    health, _unit, unavailable = battery._battery_health(str(bat))
    assert health is None
    assert unavailable


def test_no_battery_is_a_skip_not_an_error(monkeypatch):
    monkeypatch.setattr(battery.glob, "glob", lambda _pattern: [])
    with pytest.raises(Skip):
        battery.collect()


# --- wifi -------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("70.", 70.0),      # the real format from /proc/net/wireless
    ("-36.", -36.0),
    ("70", 70.0),
    ("0.", 0.0),
    (None, None),
    ("", None),
    ("n/a", None),
])
def test_proc_net_wireless_values_become_numbers(raw, expected):
    assert wifi._numeric(raw) == expected


def test_adapter_values_are_numeric_in_the_snapshot(tmp_path, monkeypatch):
    """The regression: link_quality travelled as the string "70.".

    The aggregate min_link_quality was a float while the per-adapter
    value was a string, so the same measurement had two types depending
    on where it was read.
    """
    proc = tmp_path / "wireless"
    proc.write_text(
        "Inter-| sta-|   Quality        |   Discarded packets\n"
        " face | tus | link level noise |  nwid crypt frag\n"
        "wlp8s0: 0000   70.  -36.  -256        0      0     0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(wifi, "_ssid", lambda _iface: "TestNet")

    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/proc/net/wireless":
            return real_open(proc, *args, **kwargs)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    data = wifi.collect()
    adapter = data["adapters"][0]

    assert adapter["interface"] == "wlp8s0"
    assert isinstance(adapter["link_quality"], float)
    assert isinstance(adapter["signal_level_dbm"], float)
    assert adapter["link_quality"] == 70.0
    assert adapter["signal_level_dbm"] == -36.0
    # Aggregate and per-adapter value must be the same type.
    assert type(data["min_link_quality"]) is type(adapter["link_quality"])


def test_snapshot_is_json_serialisable_with_consistent_types(tmp_path, monkeypatch):
    """Anything consuming the JSON export should not have to string-parse."""
    proc = tmp_path / "wireless"
    proc.write_text(
        "h1\nh2\nwlp8s0: 0000   70.  -36.  -256        0      0     0\n",
        encoding="utf-8")
    monkeypatch.setattr(wifi, "_ssid", lambda _iface: None)

    real_open = open
    monkeypatch.setattr("builtins.open", lambda p, *a, **k: (
        real_open(proc, *a, **k) if str(p) == "/proc/net/wireless" else real_open(p, *a, **k)))

    payload = json.loads(json.dumps(wifi.collect()))
    assert payload["adapters"][0]["link_quality"] == 70.0
