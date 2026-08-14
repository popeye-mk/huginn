"""Windows Wi-Fi collector (spec §4.2) — signal strength per adapter.

**Unverified against real hardware.** The test VM had no wireless
adapter, so only the Skip path has actually run.

Signal strength comes from `MSNdis_80211_ReceivedSignalStrength`
(root\\wmi) rather than `netsh wlan show interfaces`. netsh prints a
localised, human-formatted table — "Signal : 78%" becomes "Signaal" on
a Dutch install and the parse silently returns nothing. The NDIS class
returns an integer dBm regardless of language.

dBm is converted to the same 0-70 quality scale the Linux collector
reports from /proc/net/wireless, so `wifi_weak` means the same thing on
both platforms rather than comparing two different units that happen to
share a field name.
"""

import json

from collectors.windows._powershell import run_powershell

PS_COMMAND = r"""
$adapters = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
  Where-Object { $_.PhysicalMediaType -like '*802.11*' -or $_.InterfaceDescription -like '*Wireless*' })

$signals = @(Get-CimInstance -Namespace root\wmi -ClassName MSNdis_80211_ReceivedSignalStrength -ErrorAction SilentlyContinue)

$rows = @()
foreach ($a in $adapters) {
  $sig = $signals | Where-Object { $_.InstanceName -eq $a.InterfaceDescription } | Select-Object -First 1
  $rows += [PSCustomObject]@{
    Interface   = $a.Name
    Description = $a.InterfaceDescription
    Status      = $a.Status
    SignalDbm   = $sig.Ndis80211ReceivedSignalStrength
  }
}
[PSCustomObject]@{ Adapters = @($rows) } | ConvertTo-Json -Compress -Depth 4
""".strip()


def dbm_to_quality(dbm):
    """dBm -> the 0-70 scale the Linux collector reports.

    Maps the usable range (-90 dBm unusable, -20 dBm excellent) linearly
    onto 0-70. This is a convention, not physics: the point is that a
    single threshold in the KB means the same signal quality on both
    platforms. Clamped at both ends so a spurious reading cannot produce
    a nonsense score.
    """
    if dbm is None:
        return None
    quality = (dbm + 90) * 70 / 70.0  # -90 -> 0, -20 -> 70
    return round(max(0.0, min(70.0, quality)), 1)


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 15


def parse(raw_json):
    obj = json.loads(raw_json)

    rows = obj.get("Adapters") or []
    if isinstance(rows, dict):
        rows = [rows]

    adapters, qualities = [], []
    for row in rows:
        dbm = row.get("SignalDbm")
        quality = dbm_to_quality(dbm)
        if quality is not None:
            qualities.append(quality)
        adapters.append({
            "interface": row.get("Interface"),
            "description": row.get("Description"),
            "status": row.get("Status"),
            "signal_level_dbm": dbm,
            "link_quality": quality,
        })

    return {
        "adapters": adapters,
        "min_link_quality": min(qualities) if qualities else None,
    }


def collect():
    from collectors.base import Skip

    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    data = parse(raw)
    if not data["adapters"]:
        raise Skip("no wireless adapter detected")
    if data["min_link_quality"] is None:
        # Adapter present but no signal reading — commonly a disabled or
        # disconnected radio. Say that rather than reporting a healthy
        # link on no data.
        raise Skip("wireless adapter present but reporting no signal (radio off or not associated)")
    return data
