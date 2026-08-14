"""Windows system collector (spec §4.1) — OS version, RAM, uptime.

Uptime was deliberately omitted from earlier versions: `LastBootUpTime`
comes back from `ConvertTo-Json` in two different shapes depending on
PowerShell version, and guessing at the parsing without a machine to
check against is exactly the confidently-wrong behaviour §3.5 warns
about. A real capture (Windows 11 Pro 26200, PowerShell 5.1) settled
it — see tests/golden/win11_26200_ps51.json — and both shapes are now
handled in collectors/windows/_dates.py.

With uptime present, `system_uptime_excessive` can finally fire on
Windows. It could not before, and did so silently: the rule matched a
field that was never emitted, which the interpreter correctly treats as
missing data rather than a healthy value.
"""

import json
from datetime import datetime, timezone

from collectors.windows._dates import parse_ps_datetime
from collectors.windows._powershell import run_powershell

PS_COMMAND = (
    "Get-CimInstance Win32_OperatingSystem | "
    "Select-Object Caption, Version, FreePhysicalMemory, TotalVisibleMemorySize, LastBootUpTime | "
    "ConvertTo-Json -Compress"
)


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 10


def parse(raw_json, now=None):
    obj = json.loads(raw_json)
    total_kb = obj.get("TotalVisibleMemorySize") or 0
    free_kb = obj.get("FreePhysicalMemory") or 0

    data = {
        "os": "windows",
        "os_release": obj.get("Caption"),
        "kernel": obj.get("Version"),
        "mem_total_mb": round(total_kb / 1024, 1) if total_kb else None,
        "mem_available_mb": round(free_kb / 1024, 1) if free_kb else None,
        "mem_used_percent": round(100 * (1 - free_kb / total_kb), 1) if total_kb else None,
    }

    boot = parse_ps_datetime(obj.get("LastBootUpTime"))
    if boot is not None:
        current = now or datetime.now(timezone.utc)
        uptime_seconds = (current - boot).total_seconds()
        # A negative uptime means the clock moved, not that the machine
        # booted in the future. Report nothing rather than nonsense —
        # clock drift is itself a diagnosable condition and inventing a
        # negative uptime would mask it.
        if uptime_seconds >= 0:
            data["last_boot"] = boot.isoformat(timespec="seconds")
            data["last_boot_epoch"] = int(boot.timestamp())
            data["uptime_seconds"] = round(uptime_seconds, 2)
            data["uptime_days"] = round(uptime_seconds / 86400, 1)

    # Deliberately absent keys (uptime on an unparseable date) are left
    # out entirely rather than set to None: the interpreter distinguishes
    # a missing field from a null one, and only the latter can match a
    # rule (§3.4).
    return data


def collect():
    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    return parse(raw)
