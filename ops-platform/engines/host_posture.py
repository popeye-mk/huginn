"""Host posture (H1) — read the PRECONDITIONS that make an attack work.

Every other detector in this platform answers "is something happening?".
This one answers the question that comes *before* that: **would it work if it
were tried?** That is the only honest form of prediction available here — not
prophecy, but preconditions. the predecessor project already detects an LLMNR poisoner the
moment it answers; this reports that this host *would answer a poisoner*,
which is knowable today and fixable today.

Four readings, all unprivileged, all from this host:

- **listening ports** — the exposure scan deliberately skips our own IP
  (`s.ip != own_ip` in the patrol), so the machine the operator actually cares
  about was the one device never scanned. This closes that blind spot.
- **LLMNR** — the precondition for the poisoning `namewatch` detects.
- **IPv6 router advertisements** — the precondition for mitm6: a host that
  accepts an RA from anyone can be handed a rogue IPv6 gateway and DNS on a
  network nobody thought was running IPv6. Until now the platform did not look
  at IPv6 at all.
- **host firewall** — whether anything is filtering at all.

Every reader takes an injectable `run` so the parsing is unit-tested without
touching the machine, and returns `None` for "could not read" — never a
default that would read as "fine".
"""

import re
import subprocess

from platform_support import (
    firewall_command,
    ipv6_ra_command,
    listening_ports_command,
    llmnr_setting_command,
)

_LISTEN_LINE = re.compile(r"[\d.:*\[\]a-f]+:(\d+)\s")
_WIN_LISTEN = re.compile(r"^\s*TCP\s+\S+:(\d+)\s+\S+\s+LISTENING", re.M)


def _run(command, timeout=6):
    """Run a read-only command; return stdout or None if it could not run."""
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=timeout)
    except Exception:  # noqa: BLE001 - unreadable is None, never a false 'fine'
        return None
    if result.returncode != 0 and not (result.stdout or "").strip():
        return None
    return result.stdout or ""


def parse_listening(text):
    """Local listening ports from `ss -tulnH` or Windows `netstat -ano`."""
    if text is None:
        return None
    ports = set()
    for match in _WIN_LISTEN.finditer(text):
        ports.add(int(match.group(1)))
    if not ports:
        for line in text.splitlines():
            if "LISTEN" not in line.upper() and not line.strip().startswith(
                    ("tcp", "udp")):
                continue
            found = _LISTEN_LINE.findall(line)
            if found:
                ports.add(int(found[0]))
    return sorted(ports)


def parse_llmnr(text):
    """True when this host answers LLMNR, False when it does not, None unknown.

    Linux `resolvectl status` prints an explicit `LLMNR setting: yes|no`.
    Windows returns the EnableMulticast policy value: 0 means disabled, and an
    EMPTY result means the policy is not set — which on Windows means LLMNR is
    ON by default. Absence is the dangerous case here, so it is not None.
    """
    if text is None:
        return None
    low = text.lower()
    match = re.search(r"llmnr setting:\s*(\w+)", low)
    if match:
        return match.group(1) not in ("no", "false", "0")
    stripped = low.strip()
    if stripped in ("0", "false"):
        return False
    if stripped in ("1", "true"):
        return True
    if stripped == "":
        return True          # policy unset → Windows default is ON
    return None


def parse_ipv6_ra(text):
    """True when this host accepts IPv6 router advertisements."""
    if text is None:
        return None
    low = text.strip().lower()
    match = re.search(r"accept_ra\s*=\s*(\d+)", low)
    if match:
        return match.group(1) != "0"
    if "enabled" in low:
        return True
    if "disabled" in low:
        return False
    return None


def parse_firewall(text):
    """True when a host firewall reports itself active."""
    if text is None:
        return None
    low = text.lower()
    if "status: active" in low or re.search(r"state\s+on", low):
        return True
    if "status: inactive" in low or re.search(r"state\s+off", low):
        return False
    return None


def read_posture(run=None):
    """Read all four signals. Returns a dict; unknown values are None."""
    run = run or _run

    def _safe(builder, parser):
        try:
            return parser(run(builder()))
        except Exception:  # noqa: BLE001 - unsupported OS or missing tool
            return None

    return {
        "listening": _safe(listening_ports_command, parse_listening),
        "llmnr": _safe(llmnr_setting_command, parse_llmnr),
        "ipv6_ra": _safe(ipv6_ra_command, parse_ipv6_ra),
        "firewall": _safe(firewall_command, parse_firewall),
    }
