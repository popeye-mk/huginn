"""Host posture domain (H1) — what would let an attack succeed, before one does.

The guard's other domains report attacks in progress. This reports **standing
conditions**: facts about this host that decide whether those attacks would
work. It is the honest version of "predict before it happens" — no forecasting,
no scoring, no guessing at intent. Just: *this is true now, and this is what it
would cost you.*

Two rules keep it from becoming alarmism:

1. **A precondition is never reported as an attack.** Severity caps at
   `warning`, confidence is `certain` (we read a setting; we did not infer it),
   and every message says what it enables rather than claiming something is
   happening. `namewatch` says "someone is poisoning"; this says "you would
   answer a poisoner."
2. **Unknown is not fine.** A reading that failed produces no finding, and the
   verb reports it as unchecked — never as a pass. The same refusal the whole
   platform is built on.
"""

from typing import List

from contracts.finding import Coverage, Finding

# Ports that, listening on the operator's OWN machine, are worth naming. This
# is the same danger set the exposure scan uses on other devices — the point
# is that our own host was the one device never scanned.
_RISKY_LOCAL = {
    21: "FTP (credentials in clear text)",
    23: "Telnet (everything in clear text)",
    135: "RPC endpoint mapper",
    139: "NetBIOS session",
    445: "SMB file sharing",
    3389: "RDP (remote desktop)",
    5900: "VNC (remote desktop)",
}


def _finding(fid, machine_id, severity, message, action, plain) -> Finding:
    return Finding(
        id=fid,
        source_module="lan-anomaly",
        machine_id=machine_id,
        severity=severity,
        confidence="certain",          # we read a setting, we did not infer it
        message=message,
        coverage=Coverage(checked=1, total=1),
        suggested_action=action,
        plain_message=plain,
        tags=("security", "posture"),
    )


def _llmnr_finding(machine_id) -> Finding:
    return _finding(
        "posture_llmnr_on", machine_id, "warning",
        "This host answers LLMNR — it would trust a name-resolution poisoner",
        "Disable LLMNR (Windows: Group Policy → Computer Configuration → "
        "Administrative Templates → Network → DNS Client → 'Turn off multicast "
        "name resolution' = Enabled. Linux: set LLMNR=no in "
        "/etc/systemd/resolved.conf). Also disable NetBIOS over TCP/IP on the "
        "adapter. This is the single highest-value LAN hardening step.",
        "If someone runs a name-poisoning tool on your network, your computer "
        "would answer it and hand over login data. Turning LLMNR off removes "
        "that possibility — the attack simply stops working.")


def _ipv6_ra_finding(machine_id) -> Finding:
    return _finding(
        "posture_ipv6_ra_on", machine_id, "warning",
        "This host accepts IPv6 router advertisements — the mitm6 precondition",
        "If you do not use IPv6 on this LAN, disable it on the adapter or stop "
        "accepting RAs (Linux: net.ipv6.conf.all.accept_ra=0; Windows: "
        "Set-NetIPInterface -AddressFamily IPv6 -RouterDiscovery Disabled). If "
        "you do use IPv6, enable RA Guard on the switch.",
        "Even on a network that only uses the old addressing, a machine can "
        "announce itself as an IPv6 router and quietly become the route your "
        "traffic takes. This host would believe such an announcement.")


def _firewall_finding(machine_id) -> Finding:
    return _finding(
        "posture_firewall_off", machine_id, "warning",
        "No host firewall is active — nothing is filtering inbound connections",
        "Turn the host firewall on (Linux: `sudo ufw enable`; Windows: "
        "`netsh advfirewall set allprofiles state on`). On a LAN you share "
        "with devices you do not control, the host firewall is the last "
        "boundary you own.",
        "Nothing on this machine is currently blocking incoming connections "
        "from the rest of the network.")


def _listening_finding(port, machine_id) -> Finding:
    label = _RISKY_LOCAL[port]
    return _finding(
        f"posture_listening_{port}", machine_id, "warning",
        f"This host is listening on {port} — {label}",
        f"If you do not need {label.split(' (')[0]} on this machine, stop the "
        f"service or block the port. This is YOUR machine's own open door — "
        f"the LAN exposure scan checks the other devices, not this one.",
        f"Your own computer is accepting connections on port {port} "
        f"({label}). Anything on the network can try it.")


def assess(posture, machine_id) -> List[Finding]:
    """Turn the four readings into precondition findings. Unknown → nothing."""
    findings: List[Finding] = []
    posture = posture or {}

    if posture.get("llmnr") is True:
        findings.append(_llmnr_finding(machine_id))
    if posture.get("ipv6_ra") is True:
        findings.append(_ipv6_ra_finding(machine_id))
    if posture.get("firewall") is False:
        findings.append(_firewall_finding(machine_id))
    for port in sorted(posture.get("listening") or []):
        if port in _RISKY_LOCAL:
            findings.append(_listening_finding(port, machine_id))
    return findings


def unchecked(posture) -> List[str]:
    """Which readings could not be taken — reported, never counted as a pass."""
    posture = posture or {}
    names = {"listening": "own listening ports", "llmnr": "LLMNR setting",
             "ipv6_ra": "IPv6 router advertisements", "firewall": "host firewall"}
    return [label for key, label in names.items() if posture.get(key) is None]
