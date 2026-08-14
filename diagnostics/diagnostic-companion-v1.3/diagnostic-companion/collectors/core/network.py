"""Network collector: IP config, default gateway, DNS servers, DNS
resolution test, ping to gateway and a public target (spec §4.1).
"""

import socket
import subprocess


KNOWN_GOOD_DOMAINS = ["example.com", "cloudflare.com", "wikipedia.org"]


def _default_gateway():
    try:
        with open("/proc/net/route", encoding="utf-8") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                iface, dest, gateway, flags = fields[0], fields[1], fields[2], fields[3]
                if dest == "00000000" and int(flags, 16) & 2:
                    # gateway is little-endian hex
                    gw_int = int(gateway, 16)
                    gw = ".".join(str((gw_int >> (8 * i)) & 0xFF) for i in range(4))
                    return gw, iface
    except FileNotFoundError:
        pass
    return None, None


def _dns_servers():
    servers = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            for line in f:
                if line.startswith("nameserver"):
                    servers.append(line.split()[1])
    except FileNotFoundError:
        pass
    return servers


def _dns_resolution_test():
    results = {}
    for domain in KNOWN_GOOD_DOMAINS:
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(domain)
            results[domain] = True
        except OSError:
            results[domain] = False
    return results


def _ping(target, count=1, timeout_s=2):
    if not target:
        return {"target": target, "reachable": None}
    try:
        proc = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout_s), target],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 2,
        )
        return {"target": target, "reachable": proc.returncode == 0}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"target": target, "reachable": False}


def collect():
    gateway, iface = _default_gateway()
    dns_servers = _dns_servers()
    dns_results = _dns_resolution_test()

    data = {
        "interface": iface,
        "gateway": gateway,
        "dns_servers": dns_servers,
        "dns_resolution": dns_results,
        "dns_any_failed": any(not ok for ok in dns_results.values()),
        "gateway_ping": _ping(gateway),
        "public_ping": _ping("1.1.1.1"),
    }
    return data
