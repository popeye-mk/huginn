"""LAN name resolution — turn an IP into a friendly hostname (G1e).

A vendor tells you who made the chip; a *name* tells you what the device
is ("alex-iphone", "living-room-plug"). This asks each device its name
using primitives a normal host already has, in order of reliability:

1. **Reverse DNS (PTR)** via `socket.gethostbyaddr` — no install, and on
   most systems the resolver also answers mDNS `.local` names this way.
2. **mDNS** via `avahi-resolve` — only if present (Linux desktops).
3. **NetBIOS** via `nmblookup` — only if present (Samba); names Windows
   boxes that answer nothing else.

Every step is best-effort and short-timeout: a device that refuses to
name itself returns "" (honestly unknown), never a guess. Privacy-
randomized phones usually stay silent here — that's expected, and the
manual-label path (G1f) and the router's own list (G1g) fill the rest.
"""

import shutil
import socket
import subprocess
from typing import Optional

# A resolver query that hangs would stall the whole census, so every
# lookup is capped hard. The socket path gets its own default timeout.
_SOCKET_TIMEOUT = 1.5
_CMD_TIMEOUT = 2


def _clean(name: str) -> str:
    """Strip a trailing dot and the local domain suffix for a tidy label."""
    name = (name or "").strip().rstrip(".")
    # `host.local` / `host.lan` / `host.fritz.box` -> `host`
    for suffix in (".local", ".lan", ".fritz.box", ".home", ".home.arpa"):
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return name


def name_via_ptr(ip: str) -> str:
    """Reverse-DNS (PTR). Also catches mDNS on resolvers that bridge it."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(_SOCKET_TIMEOUT)
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return _clean(host)
    except Exception:  # noqa: BLE001 — NXDOMAIN, timeout, no PTR: unknown
        return ""
    finally:
        socket.setdefaulttimeout(old)


def name_via_avahi(ip: str) -> str:
    """mDNS `.local` via avahi-resolve, only if the tool is present."""
    if not shutil.which("avahi-resolve"):
        return ""
    try:
        out = subprocess.run(
            ["avahi-resolve", "-a", ip],
            capture_output=True, text=True, timeout=_CMD_TIMEOUT,
        )
        # output: "192.168.1.5\thostname.local"
        parts = (out.stdout or "").split()
        return _clean(parts[1]) if len(parts) >= 2 else ""
    except Exception:  # noqa: BLE001
        return ""


def name_via_netbios(ip: str) -> str:
    """NetBIOS name via nmblookup, only if the tool is present."""
    if not shutil.which("nmblookup"):
        return ""
    try:
        out = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=_CMD_TIMEOUT,
        )
        for line in (out.stdout or "").splitlines():
            # a workstation entry: "\tHOSTNAME        <00> -         ..."
            stripped = line.strip()
            if "<00>" in stripped and "<GROUP>" not in stripped:
                token = stripped.split()[0]
                if token and token != "name_query":
                    return _clean(token)
        return ""
    except Exception:  # noqa: BLE001
        return ""


def resolve_name(ip: str) -> str:
    """Best available name for an IP, or "" when nothing answers.

    Tries the cheapest, most-portable source first and stops at the first
    real answer. The order encodes trust: a PTR record is more stable than
    a NetBIOS reply.
    """
    for source in (name_via_ptr, name_via_avahi, name_via_netbios):
        name = source(ip)
        if name:
            return name
    return ""
