"""LAN anomaly engine — read the host's own network facts (G3).

Two small reads that need no root and touch nothing on the wire:

- the **default gateway** (from the routing table), and
- the **DHCP server** that issued this host's lease (from the DHCP client).

The domain compares them: a lease from a server that isn't the gateway is
the rogue-DHCP signal. The ARP side of G3 reuses the census engine's raw
neighbour-cache read (`raw_pairs`), so it lives there, not here.

As everywhere: the read either returns a value or honestly returns None.
A None is "could not determine," which the domain treats as not-checked —
never as "fine." Each OS emits different text, so each has its own small
parser; the command choice lives in platform_support.
"""

import re
import subprocess
from typing import Optional

from platform_support.commands import dhcp_server_command, gateway_command

_IPV4 = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
# nmcli DHCP4.OPTION lines: `DHCP4.OPTION[6]:dhcp_server_identifier = 192.168.1.1`
_DHCP_SERVER_OPT = re.compile(
    r"dhcp_server_identifier\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


def _run(command, timeout: int = 5) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout or ""
    except Exception:  # noqa: BLE001 — a read that can't run returns "", -> None
        return ""


def parse_gateway(text: str) -> Optional[str]:
    """First IPv4 after 'via' (Linux) or 'gateway:' (mac), else first IPv4."""
    for line in (text or "").splitlines():
        low = line.lower()
        if " via " in f" {low} " or "gateway:" in low or "nexthop" in low:
            m = _IPV4.search(line)
            if m:
                return m.group(1)
    m = _IPV4.search(text or "")            # Windows: bare NextHop line
    return m.group(1) if m else None


def parse_dhcp_server(text: str) -> Optional[str]:
    """The DHCP server identifier from nmcli / ipconfig / PowerShell output."""
    m = _DHCP_SERVER_OPT.search(text or "")
    if m:
        return m.group(1)
    # macOS `ipconfig getpacket`: `server_identifier (ip): 192.168.1.1`
    for line in (text or "").splitlines():
        if "server_identifier" in line.lower():
            m = _IPV4.search(line)
            if m:
                return m.group(1)
    # Windows: a bare IPv4 line is the DHCPServer value
    stripped = (text or "").strip()
    if _IPV4.fullmatch(stripped):
        return stripped
    return None


def read_gateway() -> Optional[str]:
    """The default gateway, or None when it can't be determined."""
    try:
        return parse_gateway(_run(gateway_command()))
    except Exception:  # noqa: BLE001
        return None


def read_dhcp_server() -> Optional[str]:
    """The DHCP server that issued our lease, or None when unknown."""
    try:
        return parse_dhcp_server(_run(dhcp_server_command()))
    except Exception:  # noqa: BLE001
        return None
