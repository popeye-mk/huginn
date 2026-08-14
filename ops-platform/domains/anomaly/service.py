"""LAN anomaly domain — the attacks a joined host CAN see (G3).

The census answers "who is here." This answers "is someone lying about who
they are." Both detectors run on signals a normal, un-privileged host
already holds — no packet capture, no root, no MITM of our own:

- **ARP spoofing / poisoning.** The neighbour cache maps IP<->MAC. Two
  fingerprints of a hijack in progress: one MAC claiming *several* IPs
  (an attacker answering ARP for everyone to sit in the middle), and one
  IP appearing on *several* MACs (two machines fighting over an address —
  the classic impersonation of the gateway). We read the RAW, un-deduped
  pairs so the duplicate the census hides is preserved here.

- **Rogue DHCP.** A second machine handing out leases can quietly
  redirect a whole segment's gateway and DNS. Without a sniffer we can't
  see *other* hosts' offers, but we can read *our own* lease: which server
  gave this host its address. If that server is not the known gateway, the
  segment has a second DHCP authority — worth a hard look.

Every claim is a `warning`, never an auto-action: a duplicate MAC is also
what a phone roaming between Wi-Fi and Ethernet looks like, and a lease
from a non-gateway server is normal on networks with a dedicated DHCP box.
The guard raises its hand; the human decides. And absence stays honest: a
signal we could not read is reported as "not checked," never "all clear."
"""

from collections import defaultdict
from typing import Dict, List, Optional

from contracts.finding import Coverage, Finding

# A MAC legitimately holding a couple of addresses (IPv4 + a stale entry,
# or a dual-homed box) is common; a MAC answering for many is not. The
# threshold keeps normal multi-homing quiet while catching a sweep-the-
# segment spoof. Tunable, deliberately conservative.
_MAC_MANY_IPS = 3


def _finding(fid, machine_id, message, action, checked, total, plain=None,
             confidence="likely") -> Finding:
    return Finding(
        id=fid,
        source_module="lan-anomaly",
        machine_id=machine_id,
        severity="warning",
        confidence=confidence,
        message=message,
        coverage=Coverage(checked=checked, total=total),
        suggested_action=action,
        plain_message=plain,
        tags=("security", "lan", "anomaly"),
    )


def _ip_to_macs(pairs) -> Dict[str, set]:
    table: Dict[str, set] = defaultdict(set)
    for s in pairs:
        table[s.ip].add(s.mac)
    return table


def _mac_to_ips(pairs) -> Dict[str, set]:
    table: Dict[str, set] = defaultdict(set)
    for s in pairs:
        table[s.mac].add(s.ip)
    return table


def _duplicate_ip_finding(ip, macs, machine_id, total) -> Finding:
    joined = ", ".join(sorted(macs))
    return _finding(
        f"arp_dup_ip_{ip}", machine_id,
        f"One IP claimed by several MACs: {ip} -> {joined}",
        "Two devices are answering for one address. If this IP is your "
        "gateway, treat it as a possible ARP spoof / MITM and investigate "
        "before trusting the network.",
        checked=len(macs), total=total,
        plain=("Two different devices are both claiming the same network "
               "address. That is exactly what an address-hijack looks like."),
        confidence="likely",
    )


def _promiscuous_mac_finding(mac, ips, machine_id, total) -> Finding:
    return _finding(
        f"arp_many_ips_{mac}", machine_id,
        f"One MAC answering for many IPs: {mac} -> {len(ips)} addresses",
        "A single device is claiming many addresses at once — the "
        "signature of an ARP-poisoning attacker sitting in the middle. "
        "Identify the device before trusting the segment.",
        checked=len(ips), total=total,
        plain=("One device is pretending to be many. This is how an "
               "attacker puts itself between you and everything else."),
        confidence="likely",
    )


def _gateway_mac(pairs, gateway_ip: Optional[str]) -> Optional[str]:
    """The MAC that owns the gateway IP, so we can exempt it below."""
    if not gateway_ip:
        return None
    for s in pairs:
        if s.ip == gateway_ip:
            return s.mac
    return None


def detect_arp_spoof(pairs, machine_id, gateway_ip=None) -> List[Finding]:
    """Find duplicate-IP and promiscuous-MAC patterns in the raw cache.

    The gateway is exempt from the promiscuous-MAC check: a router
    legitimately answers ARP for many addresses (it's the path to
    everything), so flagging it is a false positive. It is NOT exempt from
    the duplicate-IP check — if two MACs both claim the gateway's IP, that
    is exactly the impersonation we most want to catch.
    """
    findings: List[Finding] = []
    total = len(pairs)
    gw_mac = _gateway_mac(pairs, gateway_ip)
    for ip, macs in sorted(_ip_to_macs(pairs).items()):
        if len(macs) > 1:
            findings.append(_duplicate_ip_finding(ip, macs, machine_id, total))
    for mac, ips in sorted(_mac_to_ips(pairs).items()):
        if mac == gw_mac:
            continue                        # the router holding many IPs is normal
        if len(ips) >= _MAC_MANY_IPS:
            findings.append(_promiscuous_mac_finding(mac, ips, machine_id, total))
    return findings


def detect_rogue_dhcp(dhcp_server: Optional[str], gateway: Optional[str],
                      machine_id: str) -> List[Finding]:
    """Flag when our own lease came from a server that isn't the gateway.

    Both values are read from the host itself (lease file + routing table).
    When either is unknown we say so via coverage rather than guessing —
    a check we could not run is not a clean bill of health.
    """
    if not dhcp_server or not gateway:
        return []                       # unknown: reported as not-checked upstream
    if dhcp_server == gateway:
        return []
    return [_finding(
        f"rogue_dhcp_{dhcp_server}", machine_id,
        f"Lease came from a non-gateway server: DHCP {dhcp_server}, "
        f"gateway {gateway}",
        "A machine other than your router handed out this address. On a "
        "home LAN that usually means a rogue DHCP server — it can silently "
        "redirect your gateway and DNS. Confirm the DHCP server is one you "
        "run; if not, disconnect it.",
        checked=1, total=1,
        plain=("The device that gave your computer its network address is "
               "not your router. Someone may be running a fake network "
               "service that can reroute your traffic."),
        confidence="likely",
    )]


# --- flood detection by symptom (G13) --------------------------------------
#
# A gratuitous-ARP flood and DHCP starvation are packet-level attacks, and a
# joined host without a capture tap cannot see the packets. It CAN see what
# they do to the segment: a flood rewrites neighbour entries, so many devices
# change IP↔MAC at once; starvation exhausts the pool with forged MACs, so a
# burst of never-seen MACs appears in one pass. These detectors read those
# symptoms out of the census findings the guard already produces.
#
# Honest about what that means: a symptom is `likely`, not `certain`, and the
# message says the packets were not seen. A quiet result is not proof no flood
# happened — only that the segment did not churn in the window we compared.
_CHURN_THRESHOLD = 5        # IP↔MAC changes in one pass
_NEW_MAC_THRESHOLD = 10     # never-seen MACs in one pass


def _count_ids(findings, prefix) -> int:
    return sum(1 for f in (findings or []) if str(f.id).startswith(prefix))


def detect_arp_flood(census_findings, machine_id, seen=0,
                     threshold=_CHURN_THRESHOLD) -> List[Finding]:
    """Many IP↔MAC changes in one pass — the mark of a gratuitous-ARP flood."""
    churn = _count_ids(census_findings, "lan_ip_change_")
    if churn < threshold:
        return []
    return [_finding(
        "arp_flood_churn", machine_id,
        f"Address churn on {churn} device(s) in one pass — consistent with a "
        f"gratuitous-ARP flood",
        "Several devices changed their IP↔MAC pairing at once. That is what an "
        "ARP flood looks like from a joined host (the packets themselves were "
        "not captured). Check for an unknown device on the segment and, if the "
        "churn continues, disconnect the LAN from the internet while you find "
        "it.",
        checked=churn, total=max(seen, churn),
        plain=("Lots of devices on your network suddenly swapped addresses at "
               "once. That is a classic sign someone is flooding the network "
               "to redirect traffic."),
    )]


def detect_mac_flood(census_findings, machine_id, seen=0,
                     threshold=_NEW_MAC_THRESHOLD) -> List[Finding]:
    """A burst of never-seen MACs — the mark of DHCP starvation / MAC flooding."""
    fresh = _count_ids(census_findings, "lan_new_device_")
    if fresh < threshold:
        return []
    return [_finding(
        "mac_flood_burst", machine_id,
        f"{fresh} never-seen devices appeared in one pass — consistent with "
        f"DHCP starvation or MAC flooding",
        "That many new hardware addresses at once is rarely real devices. It "
        "is what a pool-exhaustion (DHCP starvation) or MAC-flooding attack "
        "looks like from a joined host. If your own machines start failing to "
        "get an address, treat it as active and disconnect the segment while "
        "you find the source.",
        checked=fresh, total=max(seen, fresh),
        plain=("A large number of brand-new devices appeared on your network "
               "at the same moment. Real networks do not grow like that — "
               "something is probably faking them."),
    )]
