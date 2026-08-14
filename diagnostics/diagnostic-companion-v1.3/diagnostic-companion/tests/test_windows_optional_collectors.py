"""Windows optional collectors (spec §4.2).

Unverified against real hardware — the test VM had no battery, no
wireless adapter and a virtual disk with no reliability counters. These
cover the parsing layer and, more importantly, the degradation paths:
absent hardware and missing privilege must present as Skip, never as a
healthy reading.
"""

import json

import pytest

from collectors.base import Skip
from collectors.windows import battery as win_battery
from collectors.windows import smart as win_smart
from collectors.windows import wifi as win_wifi


# --- battery ----------------------------------------------------------

def test_battery_health_is_full_over_designed_capacity():
    raw = json.dumps({
        "Batteries": [{"InstanceName": "BAT0", "DesignedCapacity": 50000, "FullCharged": 21000}],
        "Status": [{"Name": "BAT0", "EstimatedChargeRemaining": 64}],
    })
    data = win_battery.parse(raw)
    assert data["min_health_percent"] == 42.0
    assert data["batteries"][0]["capacity_percent"] == 64


def test_battery_with_unusable_capacity_reports_none_not_zero():
    """Firmware that reports 0 design capacity must not yield 0% health.

    0% health would fire battery_health_critical on a perfectly good
    battery. None means the rule cannot match, which is correct (§3.4).
    """
    raw = json.dumps({
        "Batteries": [{"InstanceName": "BAT0", "DesignedCapacity": 0, "FullCharged": 0}],
        "Status": [],
    })
    data = win_battery.parse(raw)
    assert data["batteries"][0]["health_percent"] is None
    assert data["min_health_percent"] is None


def test_battery_single_entry_collapsed_to_object():
    raw = json.dumps({
        "Batteries": {"InstanceName": "BAT0", "DesignedCapacity": 100, "FullCharged": 80},
        "Status": {"Name": "BAT0", "EstimatedChargeRemaining": 55},
    })
    assert win_battery.parse(raw)["min_health_percent"] == 80.0


# --- wifi -------------------------------------------------------------

@pytest.mark.parametrize("dbm,expected", [(-20, 70.0), (-55, 35.0), (-90, 0.0)])
def test_dbm_maps_onto_the_linux_quality_scale(dbm, expected):
    """One KB threshold must mean the same signal on both platforms."""
    assert win_wifi.dbm_to_quality(dbm) == expected


def test_dbm_is_clamped_at_both_ends():
    assert win_wifi.dbm_to_quality(-200) == 0.0
    assert win_wifi.dbm_to_quality(50) == 70.0


def test_wifi_weak_signal_crosses_the_kb_threshold():
    """-72 dBm is genuinely weak and must fall below the rule's 30."""
    raw = json.dumps({"Adapters": [
        {"Interface": "Wi-Fi", "Description": "Intel AX211", "Status": "Up", "SignalDbm": -72}
    ]})
    assert win_wifi.parse(raw)["min_link_quality"] < 30


def test_wifi_adapter_with_no_reading_yields_none():
    raw = json.dumps({"Adapters": [
        {"Interface": "Wi-Fi", "Description": "X", "Status": "Disabled", "SignalDbm": None}
    ]})
    assert win_wifi.parse(raw)["min_link_quality"] is None


# --- smart ------------------------------------------------------------

def test_healthy_disk_reports_no_problem():
    raw = json.dumps({"Disks": [{
        "DeviceId": "0", "FriendlyName": "Samsung SSD", "HealthStatus": "Healthy",
        "Wear": 3, "ReadErrorsUncorrected": 0,
    }]})
    assert win_smart.parse(raw)["any_reallocated"] is False


def test_uncorrected_read_errors_flag_the_disk():
    raw = json.dumps({"Disks": [{
        "DeviceId": "0", "FriendlyName": "WDC", "HealthStatus": "Healthy",
        "Wear": 10, "ReadErrorsUncorrected": 14,
    }]})
    assert win_smart.parse(raw)["any_reallocated"] is True


def test_unhealthy_status_flags_the_disk_even_with_no_error_count():
    raw = json.dumps({"Disks": [{
        "DeviceId": "0", "FriendlyName": "WDC", "HealthStatus": "Unhealthy",
        "Wear": None, "ReadErrorsUncorrected": None,
    }]})
    assert win_smart.parse(raw)["any_reallocated"] is True


def test_smart_records_that_its_sensor_differs_from_linux():
    """The Windows storage stack exposes no raw reallocated-sector count.

    Recording the source keeps the report from implying a precision the
    platform does not provide.
    """
    raw = json.dumps({"Disks": [{"DeviceId": "0", "HealthStatus": "Healthy"}]})
    assert win_smart.parse(raw)["source"] == "windows_storage_reliability_counters"


def test_smart_requires_elevation():
    """Unprivileged, the counters come back empty — which would render
    as a healthy disk. It must refuse instead."""
    with pytest.raises(Skip) as excinfo:
        win_smart.collect()
    assert "privile" in str(excinfo.value).lower()
