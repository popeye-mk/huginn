"""LAN sweep (G1b) — make the census see the whole segment, not just
the neighbours this host already talked to.

The neighbour cache only holds devices we've exchanged a frame with, so a
bare census shows the router and little else. A sweep fixes that: it sends
one probe to every address on the local /24, which makes each live device
answer — and answering populates the kernel's ARP cache, which the census
then reads. The sweep sends nothing to anywhere but the operator's own
subnet, and it is opt-in (the `census` verb decides when to call it).

`nmap -sn` is preferred when present (fast, one ARP/ICMP per host); a
threaded system-`ping` fallback covers machines without nmap. Either way
this only *provokes replies* — it does not read other hosts' traffic. It
is discovery, not interception.

Subnet detection uses the "connect a UDP socket, read the local address"
trick: no packet is actually sent, no root needed, and it returns the
address on the interface that reaches the internet — i.e. the real LAN,
not a Docker bridge.
"""

import ipaddress
import re
import shutil
import socket
import subprocess
from typing import List, Optional

from platform_support.commands import interfaces_command, ping_once_command

# Interface names that are NOT the LAN: loopback, container bridges, and
# VPN tunnels. The census must not sweep these — sweeping the VPN was the
# bug that returned an empty 10.x census while the real LAN sat on wlan0.
_VIRTUAL_IFACE = re.compile(
    r"^(lo|docker|veth|br-|virbr|tun|tap|wg|tailscale|zt|ppp|vmnet|utun|ham)"
)
# `3: wlan0    inet 192.168.1.22/24 brd ... scope global wlan0`
_IP_ADDR = re.compile(r"^\d+:\s*(?P<if>\S+)\s+inet\s+(?P<ip>\d+\.\d+\.\d+\.\d+)/(?P<prefix>\d+)")


def primary_ipv4() -> Optional[str]:
    """The host's own address on the interface that reaches the internet."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))   # no packet leaves; just picks a route
        return sock.getsockname()[0]
    except Exception:
        return None
    finally:
        sock.close()


def lan_network(ip: Optional[str] = None, prefix: int = 24):
    """The operator's LAN as an ip_network (/24 assumed), or None."""
    ip = ip or primary_ipv4()
    if not ip:
        return None
    try:
        return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    except ValueError:
        return None


def in_network(ip_str: str, network) -> bool:
    """True when ip_str is inside network — the LAN-only filter that drops
    Docker/virtual bridges (different subnet) and stray cache entries."""
    if network is None:
        return True
    try:
        return ipaddress.ip_address(ip_str) in network
    except ValueError:
        return False


def in_any(ip_str: str, networks) -> bool:
    """True when ip_str is inside any of the LAN networks (or none known)."""
    if not networks:
        return True
    return any(in_network(ip_str, n) for n in networks)


def parse_interfaces(text: str):
    """Parse `ip -o -4 addr` output into (ifname, ip_network) pairs."""
    out = []
    for line in (text or "").splitlines():
        m = _IP_ADDR.match(line.strip())
        if not m:
            continue
        try:
            net = ipaddress.ip_network(
                f"{m.group('ip')}/{m.group('prefix')}", strict=False
            )
        except ValueError:
            continue
        out.append((m.group("if"), net))
    return out


def _is_private_lan(net) -> bool:
    return net.is_private and not net.is_loopback and not net.is_link_local


def local_networks() -> List:
    """Every real LAN subnet the host is on — VPN and virtual dropped.

    This is the G1b fix: it does NOT trust the default route (which can be
    a VPN), it enumerates interfaces and keeps the private, physical ones.
    Falls back to the default-route /24 if enumeration can't run, so the
    census still sweeps *something* rather than nothing.
    """
    ifaces = []
    try:
        result = subprocess.run(
            interfaces_command(), capture_output=True, text=True, timeout=5
        )
        ifaces = parse_interfaces(result.stdout)
    except Exception:
        ifaces = []

    nets = []
    for ifname, net in ifaces:
        if _VIRTUAL_IFACE.match(ifname):
            continue
        if not _is_private_lan(net):
            continue
        if net not in nets:
            nets.append(net)

    if not nets:
        fallback = lan_network()
        if fallback is not None:
            nets.append(fallback)
    return nets


def sweep_available() -> bool:
    """Something to sweep with — nmap or a system ping."""
    return bool(shutil.which("nmap") or shutil.which("ping"))


def sweep_command(network) -> Optional[List[str]]:
    """The nmap sweep command, or None when nmap is absent (ping fallback)."""
    if shutil.which("nmap"):
        return ["nmap", "-sn", "-n", "--host-timeout", "900ms", str(network)]
    return None


def _ping_sweep(network, timeout: int) -> None:
    import concurrent.futures

    hosts = [str(h) for h in network.hosts()]

    def one(ip: str) -> None:
        try:
            subprocess.run(ping_once_command(ip), capture_output=True, timeout=2)
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        try:
            list(pool.map(one, hosts, timeout=timeout))
        except Exception:
            pass


def sweep(network, timeout: int = 90) -> None:
    """Provoke every host on the subnet to answer, populating the ARP cache.

    Best-effort and silent on failure: a sweep that couldn't run just
    means the census falls back to whatever the cache already held — the
    same honest degrade as everywhere else.
    """
    if network is None:
        return
    cmd = sweep_command(network)
    if cmd:
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout)
        except Exception:
            pass
        return
    if shutil.which("ping"):
        _ping_sweep(network, timeout)
