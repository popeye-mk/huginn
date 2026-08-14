"""LAN exposure domain — the meaning layer for G2.

The engine says which dangerous ports answer on each device. This says how
much each one matters and what to do about it, because "445 open" means
nothing to a person and "your file-sharing is open to the whole house"
means everything.

Severity is a deliberate claim per port:

- **Telnet (23), FTP (21), NetBIOS (139)** — `critical`. Cleartext or
  legacy protocols with no place on a modern LAN; an open one is both a
  direct risk and a sign of an unpatched or misconfigured device.
- **SMB (445), RDP (3389), VNC (5900)** — `critical`/`warning`. The classic
  lateral-movement doors; open to the LAN they are how one compromised
  device becomes all of them.
- **HTTP admin (80/8080), UPnP (1900)** — `warning`. An admin panel or
  UPnP surface that may be fine (a printer, a NAS) or may be an
  unauthenticated way in — worth a human's eyes.

A port that was already open last run is reported; a port **newly** open
since the baseline is the sharper signal (something changed) and says so.
Absence stays honest: a device that answered nothing is "nothing open was
seen," never "this device is secure."
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

from contracts.finding import Coverage, Finding
from engines.lan_exposure import DANGEROUS_PORTS

# port -> (severity, plain "why", "fix")
_PORT_RISK: Dict[int, tuple] = {
    23: ("critical", "Telnet sends everything — including passwords — in "
         "plain text. Anyone on your network can read it.",
         "Disable Telnet on this device; use SSH if you need remote access."),
    21: ("critical", "FTP is usually unencrypted; credentials and files "
         "cross the network in the clear.",
         "Turn off FTP or replace it with SFTP/FTPS."),
    139: ("critical", "NetBIOS is legacy Windows file-sharing with a long "
          "history of exploits.",
          "Disable NetBIOS over TCP/IP on this device."),
    445: ("critical", "SMB file-sharing open to the LAN is the classic way "
          "one infected device spreads to the rest.",
          "Restrict SMB to trusted devices, or turn off sharing if unused."),
    3389: ("warning", "Remote Desktop is open. If its password is weak or "
           "reused, anyone on the LAN can try to log in.",
           "Disable RDP if unused; otherwise require a strong password + "
           "network-level authentication."),
    5900: ("warning", "VNC remote-screen access is open, often with weak or "
           "no authentication.",
           "Disable VNC if unused; otherwise set a strong password and "
           "restrict access."),
    80: ("warning", "A plain-HTTP admin page is reachable. If it's a login "
         "panel, credentials travel unencrypted.",
         "Confirm what this is; use HTTPS and a strong password, or close it."),
    8080: ("warning", "A plain-HTTP admin page (alt port) is reachable, "
           "possibly an unauthenticated device panel.",
           "Confirm what this is; secure or close it."),
    1900: ("warning", "UPnP is exposed. Some devices let UPnP open ports "
           "automatically, which can widen your attack surface.",
           "Disable UPnP on the router/device unless you know you need it."),
}


@dataclass
class ExposureResult:
    findings: List[Finding]          # loud: unacknowledged, needs attention
    baseline: Dict[str, list]
    devices_scanned: int
    devices_exposed: int = 0
    report: List[dict] = field(default_factory=list)
    accepted: List[Finding] = field(default_factory=list)  # quiet: known-good


def _label(ip, name) -> str:
    """`192.168.1.1 [AVM Fritz!Box]` when a name is known, else the IP."""
    return f"{ip} [{name}]" if name else ip


def _finding(port, ip, name, machine_id, is_new, total) -> Finding:
    sev, why, fix = _PORT_RISK.get(
        port, ("warning", "An unusual service is exposed.", "Investigate."))
    svc = DANGEROUS_PORTS.get(port, str(port))
    new_tag = " (NEWLY opened since last scan)" if is_new else ""
    label = _label(ip, name)
    return Finding(
        id=f"exposure_{ip}_{port}",
        source_module="lan-exposure",
        machine_id=machine_id,
        severity=sev,
        confidence="certain",
        message=f"{label} exposes {svc} (port {port}){new_tag}",
        coverage=Coverage(checked=total, total=total),
        suggested_action=fix,
        plain_message=f"{name or ip}: {why}",
        tags=("security", "lan", "exposure"),
    )


def ack_id(ip, port) -> str:
    """The stable id used to acknowledge one exposure (ip+port)."""
    return f"exposure_{ip}_{port}"


def assess(scan_results, baseline, machine_id, names=None,
           acknowledged=None) -> ExposureResult:
    """Turn {ip: [open_ports]} into findings, flagging newly-opened ports.

    `scan_results` maps ip -> list of open ports. `baseline` maps ip -> list
    of previously-open ports. `names` (optional) maps ip -> friendly label
    so findings read "192.168.1.1 [AVM Fritz!Box]" instead of a bare IP.
    `acknowledged` (optional) is a set of ack-ids the operator has accepted
    as known-good; those move to the quiet `accepted` list instead of the
    loud `findings` list, so only unexpected exposures shout.

    First run (empty baseline) suppresses the "NEWLY opened" tag: on the
    first scan everything would be "new" against nothing, which is the same
    cry-wolf the census avoids on its first baseline.
    """
    baseline = dict(baseline or {})
    names = names or {}
    acknowledged = set(acknowledged or ())
    first_run = not baseline
    findings: List[Finding] = []
    accepted: List[Finding] = []
    report: List[dict] = []
    scanned = len(scan_results)
    exposed = 0
    total = scanned

    for ip, ports in sorted(scan_results.items()):
        open_ports = sorted(ports)
        prior = set(baseline.get(ip, []))
        if open_ports:
            exposed += 1
        for port in open_ports:
            is_new = (not first_run) and (port not in prior)
            f = _finding(port, ip, names.get(ip, ""), machine_id, is_new, total)
            (accepted if ack_id(ip, port) in acknowledged else findings).append(f)
        report.append({"ip": ip, "open_ports": open_ports})
        baseline[ip] = open_ports

    return ExposureResult(findings=findings, baseline=baseline,
                          devices_scanned=scanned, devices_exposed=exposed,
                          report=report, accepted=accepted)


# --- baseline persistence -------------------------------------------------

def load_exposure_baseline(path: str) -> Dict[str, list]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_exposure_baseline(path: str, baseline: Dict[str, list]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


# --- acknowledgements (findings the operator has accepted as known-good) ---

def load_acks(path: str) -> Dict[str, dict]:
    """ack-id -> {note, since}. Missing/broken file -> empty (nothing muted)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_acks(path: str, acks: Dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(acks, fh, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def add_ack(acks: Dict[str, dict], ip, port, note="") -> Dict[str, dict]:
    """Accept one exposure as known-good. Returns the updated map."""
    from datetime import datetime, timezone
    acks = dict(acks or {})
    acks[ack_id(ip, port)] = {"note": note or "",
                              "since": datetime.now(timezone.utc).isoformat()}
    return acks
