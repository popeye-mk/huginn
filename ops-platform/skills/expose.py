"""`expose` skill — the LAN exposure scan (G2).

The Network Guard's "check the doors" pass. It finds the devices on the
LAN (reusing the census), then checks each for the short set of dangerous
open ports — remote-desktop, file-sharing, cleartext admin — and reports
what each device leaves open, ranked by how much it matters, with a plain
reason and a fix.

Active but standard, and the operator's own LAN only. Nothing here
exploits anything: it opens a socket and notes whether it answers, the
same as any port checker. And it keeps the platform's absence discipline:
a device that answered nothing is "nothing open was seen," never "secure."
"""

import os
from typing import Any

from contracts.finding import sort_findings
from domains.exposure import (
    add_ack, assess, load_acks, load_exposure_baseline, save_acks,
    save_exposure_baseline,
)
from engines.lan_census import LanCensusEngine
from engines.lan_exposure import scan_host
from engines.lan_names import resolve_name
from engines.lan_sweep import in_any, local_networks, primary_ipv4, sweep, sweep_available
from platform_support import hostname

_BASELINE = os.path.join("data", "census", "exposure_baseline.json")
_ACKS = os.path.join("data", "census", "exposure_acks.json")


def _discover(engine, passive):
    """Census the LAN (sweep unless passive), return LAN sightings + networks."""
    networks = local_networks()
    own_ip = primary_ipv4()
    if not passive and networks and sweep_available():
        for net in networks:
            sweep(net)
    sightings = [
        s for s in engine.sightings()
        if in_any(s.ip, networks) and s.ip != own_ip
    ]
    if not passive:                       # name each device (best-effort)
        sightings = [s.with_name(_safe_name(s.ip)) for s in sightings]
    return sightings, networks


def _safe_name(ip):
    try:
        return resolve_name(ip)
    except Exception:  # noqa: BLE001
        return ""


def _render(result, machine_id) -> str:
    lines = ["  LAN EXPOSURE SCAN — " + machine_id, "  " + "=" * 58]
    lines.append(f"  Scanned {result.devices_scanned} device(s); "
                 f"{result.devices_exposed} with an exposed port.")
    lines.append("")

    if result.devices_scanned == 0:
        lines.append("  No devices to scan — nothing seen on the LAN. "
                     "(Not an all-clear; run a census first.)")
        return "\n".join(lines)

    if not result.findings and not result.accepted:
        lines.append("  No dangerous ports open on any device scanned.")
        lines.append("  (Only the checked ports, on devices that answered — "
                     "not a guarantee every device is safe.)")
        return "\n".join(lines)

    if result.findings:
        for f in sort_findings(result.findings):
            lines.append(f"   ! [{f.severity}] {f.message}")
            if f.plain_message:
                lines.append(f"       {f.plain_message}")
            if f.suggested_action:
                lines.append(f"       -> {f.suggested_action}")
    else:
        lines.append("  No unacknowledged exposures — nothing new to flag.")

    # The quiet section: exposures the operator has accepted as known-good.
    if result.accepted:
        lines += ["", "  Accepted (known-good, muted):"]
        for f in sort_findings(result.accepted):
            lines.append(f"   · {f.message}")
        lines.append("   (Run `expose unack <ip> <port>` to un-mute one.)")
    return "\n".join(lines)


def skill_expose(args: str, speaker: Any = None) -> str:
    """Scan the LAN's devices for dangerous open ports. Own LAN only."""
    del speaker
    engine = LanCensusEngine()
    if not engine.is_available():
        return ("The exposure scan could not read the LAN (the neighbour/ARP "
                "tool did not answer). This is not an all-clear — nothing "
                "could be scanned.")

    machine_id = hostname()
    passive = "passive" in (args or "").lower()
    sightings, _networks = _discover(engine, passive)

    scan_results = {s.ip: scan_host(s.ip) for s in sightings}
    # Label each device by its resolved name, else its vendor — so the
    # report reads "192.168.1.1 [AVM (Fritz!Box)]" not a bare IP.
    names = {s.ip: (s.name or s.vendor or "") for s in sightings}

    baseline = load_exposure_baseline(_BASELINE)
    acks = load_acks(_ACKS)
    result = assess(scan_results, baseline, machine_id, names=names,
                    acknowledged=set(acks))
    save_exposure_baseline(_BASELINE, result.baseline)

    return _render(result, machine_id)


def skill_ack(args: str, speaker: Any = None) -> str:
    """Accept an exposure as known-good: `ack <ip> <port> [note]`.

    Moves that ip+port finding into the quiet "accepted" section of future
    exposure scans, so only unexpected exposures stay loud. `unack` reverses
    it. This never changes anything on the network — it's a note to self.
    """
    del speaker
    parts = (args or "").split()
    unack = bool(parts) and parts[0].lower() in ("unack", "remove", "un-mute")
    if unack:
        parts = parts[1:]
    if len(parts) < 2:
        return ("Usage: ack <ip> <port> [note]   (e.g. `ack 192.168.1.1 21 "
                "Fritz NAS`).  Use `ack unack <ip> <port>` to un-mute.")
    ip, port = parts[0], parts[1]
    note = " ".join(parts[2:])
    acks = load_acks(_ACKS)

    if unack:
        acks.pop(f"exposure_{ip}_{port}", None)
        save_acks(_ACKS, acks)
        return f"Un-muted {ip} port {port} — it will flag again on the next scan."
    acks = add_ack(acks, ip, port, note)
    save_acks(_ACKS, acks)
    tail = f' ("{note}")' if note else ""
    return (f"Accepted {ip} port {port} as known-good{tail}. It moves to the "
            f"quiet section on the next `expose` scan.")


def register(registry) -> None:
    registry.register(
        "expose",
        skill_expose,
        aliases=[
            "exposure", "exposure scan", "open ports", "port scan",
            "scan for open ports", "dangerous ports",
            "blootstelling",                              # NL
            "exposition",                                 # FR
        ],
    )
    registry.register(
        "ack",
        skill_ack,
        aliases=[
            "acknowledge", "accept exposure", "mute finding", "known good",
        ],
    )
