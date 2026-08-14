"""Windows disk collector (spec §4.1) — free space per fixed volume.

Unverified against a real Windows box — see collectors/windows/_powershell.py.
Win32_LogicalDisk DriveType=3 is "local fixed disk", which is the
well-documented, stable part of this query; lowest-risk of the four
Windows collectors for that reason.
"""

import json

from collectors.windows._powershell import run_powershell

PS_COMMAND = (
    "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | "
    "Select-Object DeviceID, Size, FreeSpace, FileSystem | "
    "ConvertTo-Json -Compress"
)


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 10


def parse(raw_json):
    obj = json.loads(raw_json)
    rows = obj if isinstance(obj, list) else [obj]  # PS collapses single results

    volumes = []
    min_free_percent = 100.0
    for row in rows:
        total = row.get("Size") or 0
        free = row.get("FreeSpace") or 0
        free_percent = round(100 * free / total, 1) if total else 0.0
        min_free_percent = min(min_free_percent, free_percent)
        volumes.append({
            "device": row.get("DeviceID"),
            "mountpoint": row.get("DeviceID"),
            "fstype": row.get("FileSystem"),
            "total_gb": round(total / (1024 ** 3), 2) if total else None,
            "free_gb": round(free / (1024 ** 3), 2) if free else None,
            "free_percent": free_percent,
        })

    return {
        "volumes": volumes,
        "min_free_percent": min_free_percent if volumes else None,
    }


def collect():
    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    return parse(raw)
