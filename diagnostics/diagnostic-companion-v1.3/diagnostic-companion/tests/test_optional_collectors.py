"""Optional collectors (spec §4.2) on this build sandbox: no battery,
no Wi-Fi adapter, unprivileged user, no smartctl. Every one of those
must degrade to a clean Skip, never an exception that kills the run —
this is the same "unavailable -> say so" contract as the Windows
collectors, just exercised against real (not mocked) system state.
"""

import pytest

from collectors.base import Skip
from collectors.optional import battery, smart, wifi


def test_battery_skips_on_a_machine_with_no_battery():
    with pytest.raises(Skip):
        battery.collect()


def test_wifi_skips_on_a_machine_with_no_wireless_adapter():
    with pytest.raises(Skip):
        wifi.collect()


def test_smart_skips_when_unprivileged():
    with pytest.raises(Skip, match="insufficient_privileges"):
        smart.collect()
