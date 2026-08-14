"""Wi-Fi collector (spec §4.2): SSID, signal strength, link speed.
Auto-skips when there's no wireless interface at all (desktop/server/
wired laptop) — "half of real 'internet is slow' tickets are just weak
Wi-Fi", but only for machines that have Wi-Fi in the first place.
"""

import re
import subprocess

from collectors.base import Skip


def _numeric(value):
    """/proc/net/wireless writes values with a trailing dot: "70." "-36.".

    Those are display artefacts of the kernel's fixed-point formatting,
    not part of the number. Left as-is they travel through the snapshot
    as strings — the JSON export showed `"link_quality": "70."` while
    the aggregate showed `70.0`, so the same measurement had two types
    depending on where you read it. Anything consuming the per-adapter
    value (a report, a chart, an external tool) would have to know that.
    """
    if value is None:
        return None
    try:
        return float(str(value).rstrip("."))
    except (TypeError, ValueError):
        return None


def _wireless_interfaces():
    """Parse /proc/net/wireless — present on every Linux kernel, no
    extra tooling required, unlike iw/iwconfig/nmcli which may not be
    installed."""
    ifaces = []
    try:
        with open("/proc/net/wireless", encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return ifaces

    for line in lines[2:]:  # first two lines are headers
        line = line.strip()
        if not line:
            continue
        parts = line.split(":")
        iface = parts[0].strip()
        fields = parts[1].split()
        # status, link quality, signal level, noise level, ...
        ifaces.append({
            "interface": iface,
            "link_quality": _numeric(fields[1]) if len(fields) > 1 else None,
            "signal_level_dbm": _numeric(fields[2]) if len(fields) > 2 else None,
        })
    return ifaces


def _ssid(iface):
    try:
        proc = subprocess.run(
            ["iw", "dev", iface, "link"],
            capture_output=True, text=True, timeout=3,
        )
        match = re.search(r"SSID:\s*(.+)", proc.stdout)
        return match.group(1).strip() if match else None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def collect():
    ifaces = _wireless_interfaces()
    if not ifaces:
        raise Skip("no Wi-Fi adapter detected")

    for entry in ifaces:
        entry["ssid"] = _ssid(entry["interface"])

    # Already numeric from _numeric(); filter rather than re-parse, so
    # there is exactly one place that knows how to read these values.
    qualities = [e["link_quality"] for e in ifaces if e["link_quality"] is not None]

    return {
        "adapters": ifaces,
        "min_link_quality": min(qualities) if qualities else None,
    }
