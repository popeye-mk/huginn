"""`census` skill — who is on the LAN, and what changed (G1).

The first Network-Guard verb. It reads the neighbour cache, compares it
to a saved baseline, and reports the devices plus any that are new,
moved, or gone. It observes only — nothing here touches the network.

Rendering follows the platform's refusals: a run that saw nothing says
"nothing seen" (not "the LAN is clear"), and the first run says plainly
that it is establishing a baseline rather than pretending every device is
a fresh alert.
"""

import os
from typing import Any

from domains.census import census_diff, load_baseline, save_baseline
from engines.lan_census import LanCensusEngine
from engines.lan_names import resolve_name
from engines.lan_sweep import (
    in_any, local_networks, primary_ipv4, sweep, sweep_available,
)
from platform_support import hostname

# Baseline lives beside the other guard state, not with content.
_BASELINE = os.path.join("data", "census", "lan_baseline.json")

# Words that turn the sweep OFF for one run (passive, neighbour-cache only).
_PASSIVE_WORDS = ("passive", "quiet", "no sweep", "nosweep")


def _prune_non_lan(baseline, networks):
    """Drop baseline entries whose IP isn't on a real LAN.

    Old Docker/VPN addresses (e.g. 172.18.0.2) that predate the interface
    filter would otherwise linger forever and nag "no longer seen" every
    run. This keeps the baseline honest: it only remembers devices on a
    network we actually watch. With no LAN known, nothing is pruned (we
    can't tell what's stale, so we don't guess).
    """
    if not networks:
        return baseline
    return {
        mac: rec for mac, rec in (baseline or {}).items()
        if in_any(rec.get("ip", ""), networks)
    }


def _resolve_names(sightings):
    """Resolve a friendly name per sighting, in parallel. Best-effort."""
    import concurrent.futures

    if not sightings:
        return sightings

    def named(s):
        try:
            return s.with_name(resolve_name(s.ip))
        except Exception:  # noqa: BLE001
            return s

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        try:
            return list(pool.map(named, sightings, timeout=8))
        except Exception:  # noqa: BLE001
            return sightings


def _render(result, machine_id: str) -> str:
    lines = ["  LAN CENSUS — " + machine_id, "  " + "=" * 58]

    if result.seen == 0:
        lines.append("  Nothing in the neighbour cache — nothing seen.")
        lines.append("  (Not a clear LAN: this host has simply not talked "
                     "to anyone yet. A ping sweep would populate it.)")
        return "\n".join(lines)

    lines.append(f"  {result.seen} device(s) on the segment:")
    for d in result.devices:
        vend = f"  [{d['vendor']}]" if d.get("vendor") else "  [unknown]"
        # A manual label (G1f) wins over a probed name (G1e).
        shown = d.get("label") or d.get("name") or ""
        label = f"  {shown}" if shown else ""
        lines.append(f"   {d['ip']:16} {d['mac']}{vend}{label}")

    if result.new_baseline_created:
        lines += ["", "  First run — baseline established. Future runs flag "
                  "what changes."]
        return "\n".join(lines)

    changes = [f for f in result.findings]
    if not changes:
        lines += ["", "  No change since last census."]
    else:
        lines += ["", "  Changes:"]
        for f in changes:
            mark = "!" if f.severity != "info" else "-"
            lines.append(f"   {mark} [{f.severity}] {f.message}")
            if f.suggested_action:
                lines.append(f"       -> {f.suggested_action}")
    return "\n".join(lines)


def skill_census(args: str, speaker: Any = None) -> str:
    """Census the LAN: sweep the operator's own subnet, then report changes.

    The sweep (G1b) is on by default so the census sees the whole segment,
    not just neighbours already contacted — the operator opted into probing
    their own LAN. `census passive` skips it for a purely passive run.
    """
    del speaker
    engine = LanCensusEngine()
    if not engine.is_available():
        return ("LAN census is not available on this machine (the "
                "neighbour/ARP tool did not answer). This is not an "
                "all-clear — nothing could be checked.")

    machine_id = hostname()
    networks = local_networks()        # every real LAN subnet, not the VPN
    own_ip = primary_ipv4()
    passive = any(w in (args or "").lower() for w in _PASSIVE_WORDS)

    swept = False
    if not passive and networks and sweep_available():
        for net in networks:           # probe each real LAN to fill the cache
            sweep(net)
        swept = True

    # Only devices on one of our LANs, and never ourselves — this drops
    # Docker/virtual bridges (a different subnet) and our own interface.
    sightings = [
        s for s in engine.sightings()
        if in_any(s.ip, networks) and s.ip != own_ip
    ]
    # Ask each device its name (G1e). Threaded so N lookups cost ~one
    # timeout, not N. A silent device stays honestly unnamed.
    if not passive:
        sightings = _resolve_names(sightings)

    baseline = _prune_non_lan(load_baseline(_BASELINE), networks)
    result = census_diff(sightings, baseline, machine_id)
    save_baseline(_BASELINE, result.baseline)

    header = _render(result, machine_id)
    swept_names = ", ".join(str(n) for n in networks) or "no LAN found"
    note = (f"\n  (swept {swept_names})" if swept
            else "\n  (passive — neighbour cache only; run without "
                 "'passive' to sweep)")
    return header + note


def register(registry) -> None:
    registry.register(
        "census",
        skill_census,
        aliases=[
            "lan census", "who is on the network", "network devices",
            "netwerkapparaten", "wie is op het netwerk",   # NL
            "appareils réseau",                             # FR
        ],
    )
