"""`watch` skill — the passive anomaly watch (G3).

The Network Guard's alarm. It reads what a joined host can legitimately
see and checks it for the two segment attacks that don't need a packet
tap: ARP spoofing (a device impersonating another / sitting in the middle)
and rogue DHCP (a non-router server handing out leases).

Nothing here touches the network. It reads the neighbour cache, the
routing table, and the host's own DHCP lease — all local, all no-root.
And it keeps the platform's absence discipline: a signal it could not read
is reported as "not checked," and a clean run says "no anomalies in what
was checked," never "the LAN is safe."
"""

from typing import Any

from contracts.finding import sort_findings
from domains.anomaly import detect_arp_spoof, detect_rogue_dhcp
from engines.lan_anomaly import read_dhcp_server, read_gateway
from engines.lan_census import LanCensusEngine, raw_pairs
from platform_support import hostname


def _gather(engine):
    """Return (raw pairs, gateway, dhcp_server, arp_ok) — Nones are honest."""
    output = engine.run()
    arp_ok = output.exit_code == 0
    pairs = raw_pairs(str(output.payload or "")) if arp_ok else []
    return pairs, read_gateway(), read_dhcp_server(), arp_ok


def _render(machine_id, findings, arp_ok, gateway, dhcp_server, seen) -> str:
    lines = ["  LAN ANOMALY WATCH — " + machine_id, "  " + "=" * 58]

    # What could and couldn't be checked, stated plainly.
    lines.append(f"  ARP cache:   {'read ' + str(seen) + ' entries' if arp_ok else 'NOT READABLE — not checked'}")
    lines.append(f"  Gateway:     {gateway or 'unknown — not checked'}")
    lines.append(f"  DHCP server: {dhcp_server or 'unknown — rogue-DHCP not checked'}")
    lines.append("")

    if not findings:
        lines.append("  No anomalies in what was checked.")
        if not arp_ok or not gateway or not dhcp_server:
            lines.append("  (Note: some signals could not be read — this is "
                         "NOT a clean bill of health for them.)")
        return "\n".join(lines)

    lines.append(f"  {len(findings)} anomaly finding(s):")
    for f in sort_findings(findings):
        lines.append(f"   ! [{f.severity}/{f.confidence}] {f.message}")
        if f.suggested_action:
            lines.append(f"       -> {f.suggested_action}")
    return "\n".join(lines)


def skill_watch(args: str, speaker: Any = None) -> str:
    """Watch the LAN for ARP spoofing and rogue DHCP. Reads only."""
    del args, speaker
    engine = LanCensusEngine()
    if not engine.is_available():
        return ("The anomaly watch could not read the neighbour cache on "
                "this machine (the ARP tool did not answer). This is not an "
                "all-clear — the ARP-spoof check could not run.")

    machine_id = hostname()
    pairs, gateway, dhcp_server, arp_ok = _gather(engine)

    findings = detect_arp_spoof(pairs, machine_id, gateway_ip=gateway)
    findings += detect_rogue_dhcp(dhcp_server, gateway, machine_id)

    return _render(machine_id, findings, arp_ok, gateway, dhcp_server,
                   len(pairs))


def register(registry) -> None:
    registry.register(
        "guard",
        skill_watch,
        aliases=[
            "anomaly watch", "arp spoof", "rogue dhcp", "network attack",
            "netwerkaanval", "attaque réseau",
        ],
    )
