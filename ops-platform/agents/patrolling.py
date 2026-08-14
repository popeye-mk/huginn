"""Shared guard-patrol orchestration (G4/G6).

`run_patrol` runs the three Network-Guard checks — census, anomaly, exposure
— back to back and returns a PatrolResult. It lives here, under `agents/`,
because BOTH the `patrol` and `mitigate` skills need it, and the standing
rule of this project is that platform skill files never `from skills…`
import one another: the fork ships its own `skills` package, so a
cross-skill import resolves there and the whole platform fails to load
(`ModuleNotFoundError: No module named 'skills.patrol'`). Shared code lives
under `agents/`, which is unique to ops-platform and therefore collision-safe
— the same home as `recalling.py` and `recall_render.py`.
"""

import os

from domains.anomaly import (
    detect_arp_flood, detect_arp_spoof, detect_mac_flood, detect_rogue_dhcp,
)
from domains.census import census_diff, load_baseline, save_baseline
from domains.exposure import (
    assess, load_acks, load_exposure_baseline, save_exposure_baseline,
)
from domains.patrol import evaluate
from engines.lan_anomaly import read_dhcp_server, read_gateway
from engines.lan_census import LanCensusEngine, raw_pairs
from engines.lan_exposure import scan_host
from engines.lan_names import resolve_name
from engines.lan_sweep import in_any, local_networks, primary_ipv4, sweep, sweep_available
from platform_support import hostname

_CENSUS_BASELINE = os.path.join("data", "census", "lan_baseline.json")
_EXPO_BASELINE = os.path.join("data", "census", "exposure_baseline.json")
_ACKS = os.path.join("data", "census", "exposure_acks.json")


def _sightings(engine, networks, own_ip):
    named = []
    for s in engine.sightings():
        if in_any(s.ip, networks) and s.ip != own_ip:
            try:
                named.append(s.with_name(resolve_name(s.ip)))
            except Exception:  # noqa: BLE001
                named.append(s)
    return named


def run_patrol(machine_id=None):
    """Run all three checks and return a PatrolResult. Reused by the skills."""
    engine = LanCensusEngine()
    machine_id = machine_id or hostname()
    if not engine.is_available():
        return None                     # can't read the LAN; caller degrades

    networks = local_networks()
    own_ip = primary_ipv4()
    if networks and sweep_available():
        for net in networks:
            sweep(net)

    sightings = _sightings(engine, networks, own_ip)

    # Census diff (new device / IP change / vanished).
    c_base = load_baseline(_CENSUS_BASELINE)
    c_res = census_diff(sightings, c_base, machine_id)
    save_baseline(_CENSUS_BASELINE, c_res.baseline)

    # Anomaly watch (ARP spoof / rogue DHCP).
    pairs = raw_pairs(str(engine.run().payload or ""))
    gateway = read_gateway()
    a_find = detect_arp_spoof(pairs, machine_id, gateway_ip=gateway)
    a_find += detect_rogue_dhcp(read_dhcp_server(), gateway, machine_id)
    # Flood symptoms (G13) read the census diff this pass just produced: mass
    # IP↔MAC churn = gratuitous-ARP flood, a burst of new MACs = DHCP
    # starvation. Packet-level attacks seen by their effect, honestly labelled.
    a_find += detect_arp_flood(c_res.findings, machine_id, seen=c_res.seen)
    a_find += detect_mac_flood(c_res.findings, machine_id, seen=c_res.seen)

    # Exposure scan (open ports, newly-opened tagged, acks muted).
    scan_results = {s.ip: scan_host(s.ip) for s in sightings}
    names = {s.ip: (s.name or s.vendor or "") for s in sightings}
    e_base = load_exposure_baseline(_EXPO_BASELINE)
    e_res = assess(scan_results, e_base, machine_id, names=names,
                   acknowledged=set(load_acks(_ACKS)))
    save_exposure_baseline(_EXPO_BASELINE, e_res.baseline)

    return evaluate(c_res.findings, a_find, e_res.findings,
                    census_count=c_res.seen, exposed_count=e_res.devices_exposed)
