"""Windows battery collector (spec §4.2) — health vs. design capacity.

**Unverified against real hardware.** The test machine was a VM with no
battery, so this has only been exercised through its Skip path and
against canned JSON. Marked here rather than implied to be tested.

Deliberately uses the root\\WMI battery classes rather than parsing
`powercfg /batteryreport`, for two reasons:

1. `powercfg` emits a localised HTML report. Parsing it means parsing
   translated strings, which breaks on exactly the non-English installs
   spec §19 cares about. CIM property names are locale-independent.
2. `powercfg /batteryreport` writes a file to disk. This tool is
   read-only by contract (§3.2), and a collector that creates files
   violates that no matter how harmless the file is.

Health = FullChargedCapacity / DesignedCapacity, the same ratio the
Linux collector computes from /sys/class/power_supply, so the
`battery_health_low` rule means the same thing on both platforms.
"""

import json

from collectors.windows._powershell import run_powershell

PS_COMMAND = r"""
$static = @(Get-CimInstance -Namespace root\WMI -ClassName BatteryStaticData -ErrorAction SilentlyContinue)
$full   = @(Get-CimInstance -Namespace root\WMI -ClassName BatteryFullChargedCapacity -ErrorAction SilentlyContinue)
$status = @(Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue)

$rows = @()
foreach ($s in $static) {
  $match = $full | Where-Object { $_.InstanceName -eq $s.InstanceName } | Select-Object -First 1
  $rows += [PSCustomObject]@{
    InstanceName     = $s.InstanceName
    DesignedCapacity = $s.DesignedCapacity
    FullCharged      = $match.FullChargedCapacity
  }
}

[PSCustomObject]@{
  Batteries = @($rows)
  Status    = @($status | Select-Object Name, EstimatedChargeRemaining, BatteryStatus)
} | ConvertTo-Json -Compress -Depth 4
""".strip()


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 15


def parse(raw_json):
    obj = json.loads(raw_json)

    rows = obj.get("Batteries") or []
    if isinstance(rows, dict):
        rows = [rows]

    status_rows = obj.get("Status") or []
    if isinstance(status_rows, dict):
        status_rows = [status_rows]
    charge_by_name = {
        s.get("Name"): s.get("EstimatedChargeRemaining")
        for s in status_rows
        if isinstance(s, dict)
    }

    batteries, health_values = [], []
    for row in rows:
        designed = row.get("DesignedCapacity") or 0
        full = row.get("FullCharged") or 0

        # Some firmware reports 0 or omits one of the two values. A
        # health figure computed from a missing denominator would be
        # invented, so report the battery with health None instead —
        # the rule then cannot fire, which is correct (§3.4).
        health = round(100 * full / designed, 1) if designed and full else None
        if health is not None:
            health_values.append(health)

        name = row.get("InstanceName")
        batteries.append({
            "name": name,
            "designed_capacity": designed or None,
            "full_charge_capacity": full or None,
            "health_percent": health,
            "capacity_percent": charge_by_name.get(name),
        })

    return {
        "batteries": batteries,
        "min_health_percent": min(health_values) if health_values else None,
    }


def collect():
    from collectors.base import Skip

    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    data = parse(raw)
    if not data["batteries"]:
        # No battery is not a fault and not health — it is
        # inapplicable, which is what Skip means (§4.2).
        raise Skip("no battery detected (desktop, VM, or server)")
    return data
