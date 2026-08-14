"""LAN exposure scan (G2) — which dangerous doors a device leaves open.

The census says *who* is on the LAN; this says *what services they expose*.
It checks each device for a short, curated set of ports that are dangerous
to leave open on a home LAN — remote-desktop, file-sharing, and cleartext
admin protocols that are the standing targets of lateral movement.

It is an **active but standard TCP-connect scan of the operator's own LAN
only**: it opens a socket to each port and notes whether it answers. No
root, no raw packets, no exploitation — the same thing any port checker
does. `nmap` is used when present (faster, one pass); otherwise a threaded
`socket.connect_ex` fallback covers every machine.

Absence stays honest: a host that refuses the scan, or a firewall that
drops the probes, yields "no ports seen" — which the domain reports as
"nothing answered," never "this device is safe."
"""

import shutil
import socket
import subprocess
from typing import Dict, List

# The curated danger set — not a full 65k sweep. Each port here is one a
# home device should almost never expose to the LAN, and each maps to a
# specific, explainable risk in the domain layer. Keeping the set small
# keeps the scan fast and the report legible.
DANGEROUS_PORTS: Dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    139: "NetBIOS",
    80: "HTTP-admin",
    8080: "HTTP-admin-alt",
    1900: "UPnP",
}

_CONNECT_TIMEOUT = 0.6      # per-port; short so a full host scan stays quick


def scan_available() -> bool:
    """Always true — the socket fallback needs nothing installed."""
    return True


def _scan_one_port(ip: str, port: int) -> bool:
    """True if the TCP port accepts a connection (i.e. is open)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(_CONNECT_TIMEOUT)
    try:
        return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        sock.close()


def _scan_socket(ip: str, ports: List[int]) -> List[int]:
    """Threaded connect-scan of one host over the given ports."""
    import concurrent.futures

    open_ports: List[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        futures = {pool.submit(_scan_one_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            try:
                if fut.result():
                    open_ports.append(futures[fut])
            except Exception:  # noqa: BLE001
                pass
    return sorted(open_ports)


def _nmap_command(ip: str, ports: List[int]) -> List[str]:
    plist = ",".join(str(p) for p in sorted(ports))
    return ["nmap", "-Pn", "-n", "--open", "-p", plist,
            "--host-timeout", "20s", ip]


def _parse_nmap(text: str) -> List[int]:
    """Pull open ports from `nmap` grepable-ish stdout lines like `445/tcp open`."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if "/tcp" in line and "open" in line:
            try:
                out.append(int(line.split("/", 1)[0]))
            except ValueError:
                continue
    return sorted(out)


def scan_host(ip: str, ports: List[int] = None, timeout: int = 25) -> List[int]:
    """Return the open dangerous ports on one host. nmap if present, else sockets."""
    ports = ports or list(DANGEROUS_PORTS)
    if shutil.which("nmap"):
        try:
            result = subprocess.run(
                _nmap_command(ip, ports), capture_output=True,
                text=True, timeout=timeout,
            )
            return _parse_nmap(result.stdout)
        except Exception:  # noqa: BLE001 — fall back to sockets
            pass
    return _scan_socket(ip, ports)
