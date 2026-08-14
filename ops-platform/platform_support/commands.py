"""Per-OS command lines for tools that exist on both platforms.

`detect.py` answers "which binary"; this answers "which invocation".
They are separated because the questions have different shapes: netdiag
ships one binary per OS with identical arguments, while listing network
connections means `ss` on Linux and a PowerShell cmdlet on Windows —
different tool, different flags, different output format entirely.

Putting the invocation here keeps the engine free of `if windows`, which
is the rule that stops "runs on both" decaying into "runs on the one I
tested". The engine asks for a command and parses what comes back; it
never decides which command it asked for.
"""

import os
from typing import List, Optional

from contracts.errors import UnsupportedPlatformError

from .detect import LINUX, MACOS, WINDOWS, current_os

# --- listing network connections -----------------------------------------
#
# Linux: `ss` rather than `netstat` — netstat is deprecated and absent
# from minimal installs, while `ss` ships with iproute2 which is
# effectively mandatory. `-H` suppresses the header so parsing never
# depends on matching a title row that changes between versions.
#
# Windows: `Get-NetTCPConnection` rather than `netstat -ano` — it emits
# structured objects that convert to JSON, so the Windows path parses
# real data instead of scraping columns. The two platforms therefore
# have genuinely different parsers, and pretending otherwise would have
# meant writing a column scraper for an OS that did not need one.
_CONNECTION_COMMANDS = {
    LINUX: [
        "ss", "-tunH",
        # `-p` (process) is deliberately NOT requested. It needs root for
        # sockets owned by other users, and a verifier that asks for root
        # to answer a read-only question gets run less often. Process
        # attribution is a later, opt-in enrichment.
        "state", "connected",
    ],
    MACOS: ["netstat", "-anv", "-p", "tcp"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        # ConvertTo-Json with a depth and an array wrapper: a single
        # connection otherwise serialises as a bare object rather than a
        # one-element list, which is a classic Windows-only parse bug.
        "@(Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Where-Object { $_.State -eq 'Established' } | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,"
        "State,OwningProcess) | ConvertTo-Json -Depth 3 -Compress",
    ],
}


def connection_command() -> List[str]:
    """How to list established connections on this OS."""
    command = _CONNECTION_COMMANDS.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(
            "listing network connections",
            current_os(),
            tuple(_CONNECTION_COMMANDS),
        )
    return list(command)


# --- listing LAN neighbours (the ARP/neighbour cache) ---------------------
#
# G1 of the Network Guard: who is on the segment. This reads the kernel's
# ARP/neighbour cache — devices this host has recently exchanged a frame
# with (router, DNS, anything talked to). It is PASSIVE and needs no root;
# a fuller census (an active ping sweep to populate the cache) is a
# separate, opt-in step. Linux `ip neigh` and Windows `arp -a` produce
# genuinely different text, so each has its own parser in the engine.
_NEIGHBOUR_COMMANDS = {
    LINUX: ["ip", "neigh", "show"],
    MACOS: ["arp", "-a", "-n"],
    WINDOWS: ["arp", "-a"],
}


def neighbour_command() -> List[str]:
    """How to list the LAN neighbour/ARP cache on this OS."""
    command = _NEIGHBOUR_COMMANDS.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(
            "listing LAN neighbours",
            current_os(),
            tuple(_NEIGHBOUR_COMMANDS),
        )
    return list(command)


# One ICMP echo with a short deadline — the ping-sweep fallback (G1b) when
# nmap is absent. Flags differ per OS (`-c`/`-W` seconds vs `-n`/`-w` ms),
# which is exactly the kind of branch that lives here, not in the engine.
def ping_once_command(ip: str) -> List[str]:
    """Send one ping to `ip` with a sub-second timeout, per OS."""
    os_name = current_os()
    if os_name == WINDOWS:
        return ["ping", "-n", "1", "-w", "800", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


# List the host's own IPv4 interfaces (G1b fix): the census must sweep the
# LAN interface, not the default route — which may be a VPN. Each OS names
# and formats this differently, so the command choice lives here; the
# engine parses whatever text comes back.
_INTERFACES_COMMANDS = {
    LINUX: ["ip", "-o", "-4", "addr", "show"],
    MACOS: ["ifconfig"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object IPAddress,PrefixLength,InterfaceAlias | "
        "ConvertTo-Json -Compress",
    ],
}


def interfaces_command() -> List[str]:
    """How to list this host's IPv4 interfaces on this OS."""
    command = _INTERFACES_COMMANDS.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(
            "listing network interfaces",
            current_os(),
            tuple(_INTERFACES_COMMANDS),
        )
    return list(command)


# The default gateway (G3 rogue-DHCP check needs it to compare against the
# lease server). Linux/mac read the routing table; Windows uses PowerShell.
_GATEWAY_COMMANDS = {
    LINUX: ["ip", "route", "show", "default"],
    MACOS: ["route", "-n", "get", "default"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "Sort-Object RouteMetric | Select-Object -First 1).NextHop",
    ],
}

# The DHCP server that issued this host's lease. Linux reads it from the
# routing table's dhcp metadata is unreliable, so we ask NetworkManager;
# Windows asks the DHCP client service. macOS uses ipconfig.
_DHCP_SERVER_COMMANDS = {
    LINUX: ["nmcli", "-t", "-f", "DHCP4.OPTION", "connection", "show", "--active"],
    MACOS: ["ipconfig", "getpacket", "en0"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-CimInstance Win32_NetworkAdapterConfiguration | "
        "Where-Object { $_.DHCPEnabled -eq $true -and $_.DHCPServer } | "
        "Select-Object -First 1).DHCPServer",
    ],
}


def gateway_command() -> List[str]:
    """How to read the default gateway on this OS."""
    command = _GATEWAY_COMMANDS.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(
            "reading the default gateway",
            current_os(),
            tuple(_GATEWAY_COMMANDS),
        )
    return list(command)


def dhcp_server_command() -> List[str]:
    """How to read the DHCP server that issued this host's lease."""
    command = _DHCP_SERVER_COMMANDS.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(
            "reading the DHCP server",
            current_os(),
            tuple(_DHCP_SERVER_COMMANDS),
        )
    return list(command)


def connection_output_is_json() -> bool:
    """Whether this OS returns structured output.

    The parser needs to know, and asking it to sniff the payload would
    make a malformed response indistinguishable from a different format.
    """
    return current_os() == WINDOWS


# --- host posture (H1): the PRECONDITIONS that make an attack work ---------
#
# Everything above reads what is happening. These read what would let it
# happen — this host's own listening ports, whether it answers the
# name-resolution protocols a poisoner abuses, and whether it accepts router
# advertisements (the mitm6 precondition). All unprivileged reads.

_LISTENING_COMMANDS = {
    LINUX: ["ss", "-tulnH"],
    MACOS: ["netstat", "-an", "-p", "tcp"],
    WINDOWS: ["netstat", "-ano"],
}

# LLMNR: Linux keeps it in systemd-resolved's config; Windows in policy.
_LLMNR_COMMANDS = {
    LINUX: ["resolvectl", "status"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-ItemProperty -Path "
        "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "-Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast",
    ],
}

# IPv6 router advertisements — accepting them from anyone is what mitm6 uses.
_IPV6_RA_COMMANDS = {
    LINUX: ["sysctl", "net.ipv6.conf.all.accept_ra"],
    WINDOWS: [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "(Get-NetIPInterface -AddressFamily IPv6 -ErrorAction SilentlyContinue "
        "| Select-Object -First 1).RouterDiscovery",
    ],
}

_FIREWALL_COMMANDS = {
    LINUX: ["ufw", "status"],
    WINDOWS: ["netsh", "advfirewall", "show", "allprofiles", "state"],
}


def _posture_command(table, what):
    command = table.get(current_os())
    if command is None:
        raise UnsupportedPlatformError(what, current_os(), tuple(table))
    return list(command)


def listening_ports_command() -> List[str]:
    """How to list the ports THIS host is listening on."""
    return _posture_command(_LISTENING_COMMANDS, "listing listening ports")


def llmnr_setting_command() -> List[str]:
    """How to read whether this host answers LLMNR."""
    return _posture_command(_LLMNR_COMMANDS, "reading the LLMNR setting")


def ipv6_ra_command() -> List[str]:
    """How to read whether this host accepts IPv6 router advertisements."""
    return _posture_command(_IPV6_RA_COMMANDS, "reading the IPv6 RA setting")


def firewall_command() -> List[str]:
    """How to read whether a host firewall is active."""
    return _posture_command(_FIREWALL_COMMANDS, "reading the firewall state")


# --- scanning the radio ---------------------------------------------------
#
# Three operating systems, three genuinely different tools and three
# genuinely different output formats. There is no common denominator here,
# which is exactly why the invocation belongs in this file: the engine asks
# what to run and what shape the answer will be, and never decides either.
#
# Every one of these reads a CACHED scan or a passive listing. None of them
# is asked to force a fresh probe — this tool does not transmit.
_WIFI_COMMANDS = {
    # `--rescan no` is load-bearing: without it nmcli may trigger an active
    # scan, which transmits probe requests.
    LINUX: ["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY",
            "dev", "wifi", "list", "--rescan", "no"],
    # netsh reports the last scan the WLAN service performed. There is no
    # supported PowerShell cmdlet for this; netsh is the only route.
    WINDOWS: ["netsh", "wlan", "show", "networks", "mode=bssid"],
    # `airport -s` was removed in macOS 14.4. `is_available` checks for the
    # binary, so a modern Mac reports "cannot read" rather than pretending.
    MACOS: ["/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport", "-s"],
}

#: Which parser the output needs. Named rather than sniffed: guessing a
#: format from its content is how a parser silently mis-reads a locale it
#: was never shown.
_WIFI_FORMATS = {LINUX: "nmcli", WINDOWS: "netsh", MACOS: "airport"}


def wifi_scan_command() -> List[str]:
    """How this OS lists the radios it can hear, without transmitting."""
    try:
        return list(_WIFI_COMMANDS[current_os()])
    except KeyError:
        # Full three-argument form. The one-argument version this used to
        # raise crashed with a TypeError on any OS outside the known three
        # — an uncaught crash where the caller expected a clean refusal it
        # could degrade around. It never showed because the three OSes it
        # was tested on all had a command; a portability test faking a
        # fourth OS found it.
        raise UnsupportedPlatformError(
            "scanning Wi-Fi", current_os(), tuple(_WIFI_COMMANDS))


def wifi_scan_format() -> str:
    """Which parser `wifi_scan_command()` output needs."""
    try:
        return _WIFI_FORMATS[current_os()]
    except KeyError:
        raise UnsupportedPlatformError(
            "parsing a Wi-Fi scan", current_os(), tuple(_WIFI_FORMATS))


# --- desktop notification -------------------------------------------------
#
# The one channel that shows a toast on THIS machine. Each OS has a
# genuinely different mechanism, which is exactly why the choice lives here
# and not in the engine:
#
#   Linux   notify-send        (libnotify; on every desktop)
#   macOS   osascript          (built in; no install, reliable)
#   Windows — none dependency-free that this project can verify. `msg.exe`
#           is Pro/Enterprise only and `powershell` toast needs a fragile
#           WinRT script. So Windows returns None here, and the engine
#           degrades to SKIPPED pointing at ntfy — the channel built for
#           "reach me when I am not at this machine", which every OS has.
#
# Returning None is a first-class answer meaning "no desktop toast on this
# OS", distinct from "the tool is missing" — the engine tells those apart.
_LINUX_URGENCY = {"critical": "critical", "warning": "normal", "info": "low"}


def desktop_notify_probe() -> Optional[str]:
    """The binary whose presence means a desktop toast is possible here."""
    return {LINUX: "notify-send", MACOS: "osascript"}.get(current_os())


def desktop_notify_command(title: str, body: str, severity: str):
    """Argv to show a desktop toast, or None if this OS has no known way.

    Built as an argv list, never a shell string: the title and body are
    operator-facing text and must not be able to break out into a command.
    """
    os_name = current_os()
    if os_name == LINUX:
        urgency = _LINUX_URGENCY.get((severity or "").lower(), "normal")
        return ["notify-send", "--app-name=Huginn",
                f"--urgency={urgency}", title, body]
    if os_name == MACOS:
        # osascript takes the strings as script text, so quotes in them are
        # neutralised rather than passed through. AppleScript has no argv.
        safe_body = body.replace("\\", " ").replace('"', "'")
        safe_title = title.replace("\\", " ").replace('"', "'")
        return ["osascript", "-e",
                f'display notification "{safe_body}" with title "{safe_title}"']
    return None                                 # Windows and the unknown: none


# --- restricting a secret file to its owner -------------------------------
#
# On POSIX `os.chmod(0o600)` is the whole story and needs no command. On
# Windows it is nearly a no-op: it toggles the read-only attribute and does
# NOT touch the ACL, so the SMTP password inherited whatever the parent
# folder granted. `icacls` is the supported way to strip inheritance and
# grant the current user alone — the same reasoning that keeps every other
# OS difference in this file rather than in the code that stores the secret.
def restrict_file_command(path: str):
    """Argv to make `path` owner-only, or None where chmod already did it.

    Windows: remove inherited ACLs (`/inheritance:r`) and grant only the
    logged-in user full control. On POSIX this returns None, because the
    0o600 the caller already set is the guarantee and running a command
    would be theatre.
    """
    if current_os() != WINDOWS:
        return None
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    grant = f"{user}:F" if user else "%USERNAME%:F"
    return ["icacls", path, "/inheritance:r", "/grant:r", grant]
