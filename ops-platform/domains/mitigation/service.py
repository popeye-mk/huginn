"""Mitigation advice (G6) — the exact fix, for the HUMAN to run.

The rest of the guard warns. This turns a confirmed warning into a
copy-pasteable mitigation with a plain explanation — a firewall rule, a
router step, a "disable this service" command — so the operator can act
fast without googling the syntax.

The hard line, enforced by construction: **this module recommends, it does
not act.** It imports nothing that can touch the network or the system —
no subprocess, no socket, no os-exec. It only formats strings. Every
mitigation it returns is explicitly labelled as something the operator runs
by hand. Autonomous blocking is not built here and never will be; that is a
safety decision, not an unfinished feature. (A test asserts this module
imports no execution primitive.)

Mitigations are keyed off the finding id patterns the other domains emit:
`exposure_<ip>_<port>`, `rogue_dhcp_<ip>`, `arp_dup_ip_<ip>`,
`arp_many_ips_<mac>`, `lan_new_device_<mac>`.
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class Mitigation:
    """One recommended fix. `command` is copy-pasteable; the operator runs it."""

    finding_id: str
    title: str
    why: str            # plain-language reason
    steps: str          # what to do (router UI path or the idea)
    command: str        # a concrete, copy-pasteable command ("" if UI-only)

    def as_text(self) -> str:
        lines = [f"  ▸ {self.title}",
                 f"    Why: {self.why}",
                 f"    Do:  {self.steps}"]
        if self.command:
            lines.append(f"    Run (you, by hand):  {self.command}")
        return "\n".join(lines)


# --- per-port service mitigations (exposure findings) ---------------------
# command uses ufw as the common Linux host firewall; the step text covers
# the router / device case for non-Linux targets.
_PORT_FIX = {
    23: ("Close Telnet (port 23)",
         "Telnet is plaintext and has no safe use on a modern LAN.",
         "Disable the Telnet service on the device; if it's yours and needs "
         "remote access, use SSH instead.",
         "sudo ufw deny from any to any port 23"),
    21: ("Close FTP (port 21)",
         "FTP sends credentials and files in clear text.",
         "Turn off FTP on the device, or switch to SFTP/FTPS. On a Fritz!Box "
         "NAS: Home Network → USB/Storage → uncheck 'Access via FTP'.",
         "sudo ufw deny from any to any port 21"),
    445: ("Restrict SMB (port 445)",
          "Open SMB is the classic lateral-movement path between devices.",
          "Limit SMB to trusted hosts, or disable file sharing if unused.",
          "sudo ufw deny from any to any port 445"),
    139: ("Disable NetBIOS (port 139)",
          "Legacy Windows sharing with a long exploit history.",
          "Turn off NetBIOS over TCP/IP in the adapter's advanced settings.",
          "sudo ufw deny from any to any port 139"),
    3389: ("Lock down RDP (port 3389)",
           "Remote Desktop open to the LAN invites password-guessing.",
           "Disable RDP if unused; else require Network-Level Auth + a strong "
           "password, and restrict source IPs.",
           "sudo ufw deny from any to any port 3389"),
    5900: ("Lock down VNC (port 5900)",
           "VNC often ships with weak or no authentication.",
           "Disable VNC if unused; else set a strong password and restrict "
           "access.",
           "sudo ufw deny from any to any port 5900"),
    80: ("Secure the HTTP admin page (port 80)",
         "A plain-HTTP admin panel sends its login unencrypted.",
         "Use the device's HTTPS page instead, set a strong password, or "
         "disable remote admin. If it's a needed device UI on your own LAN, "
         "you can accept it (`ack <ip> 80`).",
         ""),
    8080: ("Secure the HTTP admin page (port 8080)",
           "A plain-HTTP admin panel (alt port) sends its login unencrypted.",
           "Use HTTPS, set a strong password, or close the panel.",
           ""),
    1900: ("Disable UPnP (port 1900)",
           "UPnP can let devices open ports automatically, widening exposure.",
           "Turn off UPnP on the router/device unless you know you need it "
           "(Fritz!Box: Internet → Permit Access → uncheck UPnP).",
           ""),
}


def _exposure_mitigation(fid) -> Optional[Mitigation]:
    # id shape: exposure_<ip>_<port>
    parts = fid.split("_")
    try:
        port = int(parts[-1])
        ip = parts[-2]
    except (ValueError, IndexError):
        return None
    fix = _PORT_FIX.get(port)
    if not fix:
        return None
    title, why, steps, command = fix
    steps = steps.replace("<ip>", ip)
    return Mitigation(fid, f"{title} on {ip}", why, steps, command)


def _rogue_dhcp_mitigation(fid) -> Mitigation:
    ip = fid[len("rogue_dhcp_"):]
    return Mitigation(
        fid, f"Shut down the rogue DHCP server at {ip}",
        "A non-router device is handing out leases — it can redirect your "
        "gateway and DNS (a quiet man-in-the-middle).",
        "Physically locate the device at that IP and disconnect it, or block "
        "its port on a managed switch. Confirm only your router runs DHCP "
        "(Fritz!Box: Home Network → Network → Network Settings → IPv4).",
        "")


def _arp_spoof_mitigation(fid) -> Mitigation:
    return Mitigation(
        fid, "Contain the ARP-spoofing device",
        "A device is impersonating another (likely the gateway) to sit in "
        "the middle of your traffic — an active attack.",
        "Identify the offending MAC from the finding, find its switch port, "
        "and disconnect it. On the router, pin the gateway's MAC↔IP (static "
        "ARP) for known devices. Do not trust the segment until it's gone.",
        "")


def _new_device_mitigation(fid) -> Mitigation:
    mac = fid[len("lan_new_device_"):]
    return Mitigation(
        fid, f"Verify or block the new device {mac}",
        "A device you may not recognise joined the LAN.",
        "Confirm it's yours in the router's device list. If not, block it: "
        "Fritz!Box → Home Network → Network → (device) → uncheck 'This device "
        "may access the internet', or set Wi-Fi to only allow known devices.",
        "")


def _flood_mitigation(fid) -> Mitigation:
    """G13: mass churn / a burst of forged MACs — a flood in progress."""
    churn = fid == "arp_flood_churn"
    what = ("Address churn across many devices at once" if churn
            else "A burst of never-seen hardware addresses")
    return Mitigation(
        fid,
        "Contain the flood on the segment",
        f"{what} — the signature of a flooding attack (gratuitous ARP, or "
        f"DHCP-pool starvation). The packets were not captured; this is the "
        f"effect, seen from a joined host.",
        "Treat it as active. Disconnect the LAN's uplink while you work, then "
        "find the source: check the router's device list for unfamiliar "
        "entries, and on a managed switch look for one port carrying the "
        "traffic (enable port security / DHCP snooping there). Bring the "
        "uplink back only once the churn stops.",
        "")


def mitigation_for(finding) -> Optional[Mitigation]:
    """Map one finding to a recommended, human-run mitigation (or None)."""
    fid = getattr(finding, "id", "") or ""
    if fid.startswith("exposure_"):
        return _exposure_mitigation(fid)
    if fid.startswith("rogue_dhcp_"):
        return _rogue_dhcp_mitigation(fid)
    if fid.startswith("arp_dup_ip_") or fid.startswith("arp_many_ips_"):
        return _arp_spoof_mitigation(fid)
    if fid in ("arp_flood_churn", "mac_flood_burst"):
        return _flood_mitigation(fid)
    if fid.startswith("lan_new_device_"):
        return _new_device_mitigation(fid)
    return None


def mitigations_for(findings) -> List[Mitigation]:
    """Every available mitigation for a set of findings, order preserved."""
    out = []
    for f in findings or []:
        m = mitigation_for(f)
        if m is not None:
            out.append(m)
    return out
