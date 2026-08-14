"""System collector: OS version, uptime, last boot time, CPU/RAM snapshot.

Linux-only for v0 (spec targets Windows + Linux; Windows collectors are
future work — see Diagnostic_Companion_Next_Steps.md).
"""

import platform
import time


def collect():
    data = {
        "os": platform.system().lower(),
        "os_release": platform.freedesktop_os_release().get("PRETTY_NAME")
        if hasattr(platform, "freedesktop_os_release")
        else platform.platform(),
        "kernel": platform.release(),
    }

    with open("/proc/uptime", encoding="utf-8") as f:
        uptime_seconds = float(f.read().split()[0])
    data["uptime_seconds"] = uptime_seconds
    data["uptime_days"] = round(uptime_seconds / 86400, 2)
    data["last_boot_epoch"] = int(time.time() - uptime_seconds)

    with open("/proc/loadavg", encoding="utf-8") as f:
        load1, load5, load15 = f.read().split()[:3]
    data["load_avg_1m"] = float(load1)
    data["load_avg_5m"] = float(load5)
    data["load_avg_15m"] = float(load15)

    mem = {}
    with open("/proc/meminfo", encoding="utf-8") as f:
        for line in f:
            key, _, rest = line.partition(":")
            mem[key.strip()] = int(rest.strip().split()[0])  # kB
    total_kb = mem.get("MemTotal", 0)
    avail_kb = mem.get("MemAvailable", 0)
    data["mem_total_mb"] = round(total_kb / 1024, 1)
    data["mem_available_mb"] = round(avail_kb / 1024, 1)
    data["mem_used_percent"] = (
        round(100 * (1 - avail_kb / total_kb), 1) if total_kb else None
    )

    return data
