"""Battery collector (spec §4.2): health %, cycle count.

Auto-skips on desktops and servers with no battery — a normal outcome,
not an error (§3.4, §3.7 "unavailable -> say so").

**Health is computed from whichever unit the firmware reports.** The
kernel exposes battery capacity in one of two unit families depending
on the hardware:

    energy_full / energy_full_design   watt-hours  (µWh)
    charge_full / charge_full_design   amp-hours   (µAh)

Both are standard and neither is universal — laptops differ by vendor
and by battery. An earlier version read only `energy_*`, so on any
machine reporting `charge_*` the health figure came back null, and both
battery rules became structurally unfireable. That failed silently:
the collector reported status "ok", the report showed no battery
finding, and nothing distinguished "the battery is fine" from "health
was never calculated". Found on a real Acer laptop that reports
`charge_*`.

When health genuinely cannot be determined, `health_unavailable` says
so explicitly rather than leaving a bare null for a reader to interpret.
"""

import glob
import os

from collectors.base import Skip

# Tried in order. Each entry is (full, design, unit) — the first pair
# where both files exist and the design value is positive wins.
CAPACITY_SOURCES = (
    ("energy_full", "energy_full_design", "Wh"),
    ("charge_full", "charge_full_design", "Ah"),
)


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _read_int(path):
    raw = _read(path)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _battery_health(bat_path):
    """Returns (health_percent, unit, unavailable_reason)."""
    seen_any = False
    for full_name, design_name, unit in CAPACITY_SOURCES:
        full = _read_int(os.path.join(bat_path, full_name))
        design = _read_int(os.path.join(bat_path, design_name))

        if full is None and design is None:
            continue
        seen_any = True

        if full is None or design is None:
            continue
        if design <= 0:
            # Firmware occasionally reports a zero design capacity.
            # Dividing by it would either crash or invent a number.
            continue

        return round(100 * full / design, 1), unit, None

    if not seen_any:
        return None, None, "firmware reports neither energy_* nor charge_* capacity"
    return None, None, "capacity files present but incomplete or zero"


def collect():
    batteries = sorted(glob.glob("/sys/class/power_supply/BAT*"))
    if not batteries:
        raise Skip("no battery present (desktop/server, or not a laptop)")

    result = []
    for bat_path in batteries:
        health_percent, unit, unavailable = _battery_health(bat_path)

        entry = {
            "name": os.path.basename(bat_path),
            "capacity_percent": _read_int(os.path.join(bat_path, "capacity")),
            "status": _read(os.path.join(bat_path, "status")),
            "cycle_count": _read_int(os.path.join(bat_path, "cycle_count")),
            "health_percent": health_percent,
            "health_unit": unit,
        }
        # Only present when health is genuinely unobtainable, so a
        # reader never has to guess whether null means "healthy" or
        # "not measured" (§3.4).
        if unavailable:
            entry["health_unavailable"] = unavailable
        result.append(entry)

    health_values = [b["health_percent"] for b in result if b["health_percent"] is not None]

    data = {
        "batteries": result,
        "min_health_percent": min(health_values) if health_values else None,
    }
    if not health_values:
        data["health_unavailable"] = (
            "battery present, but this firmware does not expose the capacity "
            "figures needed to calculate wear"
        )
    return data
