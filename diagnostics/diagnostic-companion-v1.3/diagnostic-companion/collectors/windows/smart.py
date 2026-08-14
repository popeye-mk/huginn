"""Windows disk health collector (spec §4.2).

**Unverified against real hardware.** The test VM's virtual disk
exposes no reliability counters, so only the Skip path has run.

Uses `Get-PhysicalDisk` plus `Get-StorageReliabilityCounter` rather
than shipping smartctl. Bundling a third-party binary would mean
signing it, shipping it, and explaining it to Defender (§13.1) — a
large cost for data Windows already exposes.

The tradeoff is honest and worth stating: the Storage stack does not
expose a raw reallocated-sector count the way smartctl does. It exposes
`ReadErrorsUncorrected`, `Wear`, and a rolled-up `HealthStatus`. So
`any_reallocated` here is derived from uncorrected read errors, which
is the closest available signal for "the drive is remapping and
failing", not the identical measurement. A technician reading
`smart_reallocated` on Windows is being told something true, but from a
different sensor than on Linux — recorded in the data as `source` so
the report can never imply more precision than the platform gives.

Requires elevation: Get-StorageReliabilityCounter returns nothing
useful unprivileged, and returning nothing must present as a Skip, not
as a healthy disk (§3.4).
"""

import json

from collectors.base import Skip, require_privilege
from collectors.windows._powershell import run_powershell

PS_COMMAND = r"""
$rows = @()
foreach ($d in @(Get-PhysicalDisk -ErrorAction SilentlyContinue)) {
  $c = $null
  try { $c = $d | Get-StorageReliabilityCounter -ErrorAction Stop } catch { }
  $rows += [PSCustomObject]@{
    DeviceId              = $d.DeviceId
    FriendlyName          = $d.FriendlyName
    MediaType             = "$($d.MediaType)"
    HealthStatus          = "$($d.HealthStatus)"
    OperationalStatus     = "$($d.OperationalStatus)"
    Wear                  = $c.Wear
    ReadErrorsUncorrected = $c.ReadErrorsUncorrected
    Temperature           = $c.Temperature
    PowerOnHours          = $c.PowerOnHours
  }
}
[PSCustomObject]@{ Disks = @($rows) } | ConvertTo-Json -Compress -Depth 4
""".strip()

# Windows rolls health into three states. Anything other than Healthy
# is worth surfacing; "Unhealthy" is unambiguous.
UNHEALTHY_STATES = {"unhealthy", "warning"}


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 30


def parse(raw_json):
    obj = json.loads(raw_json)

    rows = obj.get("Disks") or []
    if isinstance(rows, dict):
        rows = [rows]

    disks = []
    any_uncorrected = False
    any_unhealthy = False
    max_wear = 0

    for row in rows:
        uncorrected = row.get("ReadErrorsUncorrected")
        health_status = (row.get("HealthStatus") or "").strip().lower()
        wear = row.get("Wear")

        if uncorrected:
            any_uncorrected = True
        if health_status in UNHEALTHY_STATES:
            any_unhealthy = True
        if isinstance(wear, (int, float)):
            max_wear = max(max_wear, wear)

        disks.append({
            "device": row.get("DeviceId"),
            "model": row.get("FriendlyName"),
            "media_type": row.get("MediaType"),
            "health": row.get("HealthStatus"),
            "operational_status": row.get("OperationalStatus"),
            "wear_percent": wear,
            "read_errors_uncorrected": uncorrected,
            "temperature_c": row.get("Temperature"),
            "power_on_hours": row.get("PowerOnHours"),
        })

    return {
        "disks": disks,
        # Named to match the Linux collector so one KB rule covers both,
        # with `source` recording that the underlying sensor differs.
        "any_reallocated": bool(any_uncorrected or any_unhealthy),
        "max_pending_sectors": 0,  # not exposed by the Windows storage stack
        "max_wear_percent": max_wear or None,
        "source": "windows_storage_reliability_counters",
    }


def collect():
    # Unprivileged, the reliability counters come back empty, which
    # would render as a healthy disk. Refuse rather than mislead.
    require_privilege("elevated")

    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    data = parse(raw)
    if not data["disks"]:
        raise Skip("no physical disks reported by the storage stack")
    return data
