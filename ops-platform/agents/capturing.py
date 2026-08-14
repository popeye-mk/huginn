"""Shared incident capture (H2) — freeze volatile state, from anywhere.

Lives here, under `agents/`, because BOTH the `capture` verb and the `patrol`
loop need it. The standing rule of this project is that platform skill files
never `from skills…` import one another — the fork's own `skills` package
shadows ours and the whole platform fails to load (that was a live outage).
Shared code lives under `agents/`, the same home as `patrolling.py`.

Everything here only READS state this host already holds: no scan, no probe,
no packet. That is what makes it safe to run automatically the moment an alert
fires, while whatever is happening is still happening.
"""

import os
from datetime import datetime, timezone

from domains.incident import build_snapshot, save_snapshot
from domains.timeline import summarize
from engines.host_posture import read_posture
from engines.lan_anomaly import read_dhcp_server, read_gateway
from engines.lan_census import LanCensusEngine, raw_pairs
from engines.lan_sweep import local_networks
from platform_support import hostname

INCIDENT_DIR = os.path.join("data", "census", "incidents")
_TIMELINE_JOURNAL = os.path.join("data", "census", "guard_events.json")


def _safe(fn, *args):
    """A reader that fails returns None — 'not readable', never 'nothing'."""
    try:
        return fn(*args)
    except Exception:  # noqa: BLE001
        return None


def collect():
    """Every volatile signal this host holds, read right now."""
    engine = LanCensusEngine()
    neighbours = None
    if _safe(engine.is_available):
        raw = _safe(lambda: str(engine.run().payload or ""))
        if raw is not None:
            # raw_pairs returns Sighting OBJECTS, not (ip, mac) tuples — its
            # docstring says "every (ip, mac) the cache holds", which describes
            # the meaning, not the shape. Unpacking them as tuples is what
            # broke `capture` in live use ("cannot unpack non-iterable
            # Sighting object"); the anomaly domain reads `s.ip`/`s.mac` and
            # was right all along.
            sightings = _safe(raw_pairs, raw)
            neighbours = [
                {"ip": s.ip, "mac": s.mac, "vendor": getattr(s, "vendor", "")}
                for s in (sightings or [])
            ]

    posture = _safe(read_posture) or {}
    timeline = _safe(summarize, _TIMELINE_JOURNAL, 7)

    return {
        "neighbours": neighbours,
        "gateway": _safe(read_gateway),
        "dhcp_server": _safe(read_dhcp_server),
        "local_networks": [str(n) for n in (_safe(local_networks) or [])],
        "listening_ports": posture.get("listening"),
        "llmnr_answers": posture.get("llmnr"),
        "ipv6_accepts_ra": posture.get("ipv6_ra"),
        "firewall_active": posture.get("firewall"),
        "recent_changes": [
            {"severity": c.severity, "message": c.message, "count": c.count,
             "last": c.last_ts}
            for c in (timeline.changes if timeline else [])
        ] if timeline else None,
    }


def take_snapshot(machine_id=None, reason="manual", directory=INCIDENT_DIR):
    """Capture now. Returns (snapshot, path) — path is "" if it could not save.

    `reason` records WHY the capture happened ("manual", or the alert that
    triggered it), so a folder of incident files can be read back without
    guessing which ones were automatic.
    """
    machine_id = machine_id or hostname()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sections = collect()
    sections["capture_reason"] = reason
    snapshot = build_snapshot(machine_id, now, sections)
    try:
        return snapshot, save_snapshot(directory, snapshot)
    except OSError:
        return snapshot, ""
