"""LAN census engine — who is on the network segment (G1).

The first stone of the Network Guard. It reads the kernel's ARP/neighbour
cache and returns one record per device seen: IP, MAC, and a best-effort
vendor from the MAC's OUI prefix. **It only observes** — passive, no root,
no probes sent. Deciding what a new or changed device *means* is the
domain layer's job, exactly like every other engine here; a collector
that shouted "unknown MAC = intruder" on its own is how a guard starts
crying wolf.

Honest limit, stated at the source: the neighbour cache holds only
devices this host has recently exchanged a frame with (router, DNS,
whatever was talked to). A full segment census needs an active ping sweep
to populate the cache first — a separate, opt-in step, not this one.

Linux (`ip neigh`) and Windows (`arp -a`) emit genuinely different text,
so each has its own parser. Both are exercised by tests against captured
output from the other OS, which is otherwise unreachable.
"""

import os
import re
from dataclasses import dataclass
from typing import List, Optional

from engines.base import DEFAULT_TIMEOUT, EngineOutput, run_command
from platform_support.commands import neighbour_command

NAME = "lan_census"
LIST_TIMEOUT = 20

# A device with no MAC is not a sighting — it is a cache entry for an
# address that never answered. `ip neigh` marks those FAILED/INCOMPLETE.
_DEAD_STATES = {"FAILED", "INCOMPLETE"}

# `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`
_IP_NEIGH = re.compile(
    r"^(?P<ip>[0-9a-fA-F:.]+)\s+dev\s+\S+"
    r"(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{17}))?"
    r"(?:\s+(?P<state>[A-Z]+))?",
)
# `  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic`  (Windows arp -a)
_ARP_A = re.compile(
    r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mac>[0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+",
)

# A curated OUI table — enough to name the common kit on a home or
# small-office LAN and to make "unknown vendor" mean something. Not a full
# IEEE registry (30k+ entries); vendor is a hint, never a verdict. When a
# prefix isn't here, the bundled `data/oui/oui-prefixes.txt` file is
# consulted (see `_lookup_bundled`), and only then do we fall back to "".
_OUI = {
    # --- routers / networking ---
    "02:1a:20": "AVM (Fritz!Box)", "d8:eb:97": "AVM (Fritz!Box)",
    "3c:a6:2f": "AVM (Fritz!Box)", "e0:28:6d": "AVM (Fritz!Box)",
    "50:c7:bf": "TP-Link", "a4:2b:b0": "TP-Link", "14:cc:20": "TP-Link",
    "ec:08:6b": "TP-Link", "b0:be:76": "TP-Link", "02:1a:2d": "TP-Link",
    "fc:ec:da": "Ubiquiti", "78:8a:20": "Ubiquiti", "24:5a:4c": "Ubiquiti",
    "00:1a:2b": "Cisco", "00:1b:0c": "Cisco", "00:23:04": "Cisco",
    "00:24:9b": "Action Star",
    # --- IoT / smart home ---
    "02:1a:23": "Tuya (smart home)", "68:3a:48": "Samjin (SmartThings)",
    "18:b4:30": "Nest", "64:16:66": "Nest", "d0:73:d5": "LIFX",
    "b0:c5:54": "D-Link", "00:1e:b8": "Aloys", "02:1a:27": "Seongji",
    "cc:50:e3": "Espressif (ESP)", "24:0a:c4": "Espressif (ESP)",
    "a0:20:a6": "Espressif (ESP)", "dc:4f:22": "Espressif (ESP)",
    # --- phones / laptops / consumer ---
    "00:1a:11": "Google", "3c:5a:b4": "Google", "f4:f5:e8": "Google",
    "00:1b:63": "Apple", "3c:07:54": "Apple", "a4:83:e7": "Apple",
    "f0:18:98": "Apple", "ac:de:48": "Apple", "dc:2b:2a": "Apple",
    "00:12:fb": "Samsung", "00:15:99": "Samsung", "5c:0a:5b": "Samsung",
    "e8:50:8b": "Samsung", "8c:77:12": "Samsung",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    # --- virtual / NIC chipsets ---
    "00:50:56": "VMware", "00:0c:29": "VMware", "00:1c:14": "VMware",
    "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
    "00:15:5d": "Microsoft Hyper-V", "00:1d:d8": "Microsoft",
    "00:e0:4c": "Realtek", "1c:1b:0d": "Gigabyte", "d8:5e:d3": "AzureWave",
}

# The bundled full-ish prefix file, consulted when _OUI misses. Loaded once
# and cached. Missing file → empty map → honest "" (never a wrong guess).
_BUNDLED_PATH = os.path.join(
    os.path.dirname(__file__), "..", "data", "oui", "oui-prefixes.txt"
)
_bundled_cache: Optional[dict] = None


def _load_bundled() -> dict:
    """Load `AABBCC Vendor` lines into a {prefix: vendor} map, once."""
    global _bundled_cache
    if _bundled_cache is not None:
        return _bundled_cache
    table: dict = {}
    try:
        with open(_BUNDLED_PATH, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2 or len(parts[0]) != 6:
                    continue
                hexp = parts[0].lower()
                key = f"{hexp[0:2]}:{hexp[2:4]}:{hexp[4:6]}"
                table[key] = parts[1].strip()
    except OSError:
        pass
    _bundled_cache = table
    return table


@dataclass(frozen=True)
class Sighting:
    """One device seen on the segment."""

    ip: str
    mac: str          # normalised: lowercase, colon-separated
    vendor: str       # "" when the OUI is unknown
    name: str = ""    # friendly hostname (G1e), "" when nothing answered

    def with_name(self, name: str) -> "Sighting":
        """A copy carrying a resolved name (Sighting is frozen)."""
        return Sighting(ip=self.ip, mac=self.mac, vendor=self.vendor,
                        name=name or "")

    def as_dict(self) -> dict:
        return {"ip": self.ip, "mac": self.mac, "vendor": self.vendor,
                "name": self.name}


def _normalise_mac(mac: str) -> str:
    return mac.replace("-", ":").lower()


def vendor_for(mac: str) -> str:
    """Best-effort vendor from the OUI prefix, or a correct classification.

    A known OUI wins. Otherwise: if the address is *locally administered*
    (bit 0x02 of the first octet), it's a privacy-randomized MAC — modern
    phones and OSes rotate these per network. That's a real, useful label
    ("randomized MAC"), not a vendor guess, and worth more here than a
    wrong name would be. Truly unknown globally-unique OUIs return "".
    """
    known = _OUI.get(mac[:8], "")
    if known:
        return known
    try:
        if int(mac[:2], 16) & 0x02:
            return "randomized MAC"
    except ValueError:
        pass
    return _load_bundled().get(mac[:8], "")


def _build(ip: str, mac: str) -> Sighting:
    mac = _normalise_mac(mac)
    return Sighting(ip=ip, mac=mac, vendor=vendor_for(mac))


def parse_ip_neigh(text: str) -> List[Sighting]:
    """Parse Linux `ip neigh show` output into sightings."""
    out = []
    for line in (text or "").splitlines():
        m = _IP_NEIGH.match(line.strip())
        if not m or not m.group("mac"):
            continue
        if (m.group("state") or "") in _DEAD_STATES:
            continue
        out.append(_build(m.group("ip"), m.group("mac")))
    return _dedupe(out)


def parse_arp_a(text: str) -> List[Sighting]:
    """Parse Windows/macOS `arp -a` output into sightings."""
    out = []
    for line in (text or "").splitlines():
        m = _ARP_A.match(line)
        if not m:
            continue
        mac = m.group("mac")
        if mac.lower() in ("ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"):
            continue  # broadcast, not a device
        out.append(_build(m.group("ip"), mac))
    return _dedupe(out)


def _dedupe(sightings: List[Sighting]) -> List[Sighting]:
    """One row per MAC; first IP seen wins (stable, testable)."""
    seen = set()
    kept = []
    for s in sightings:
        if s.mac in seen:
            continue
        seen.add(s.mac)
        kept.append(s)
    return kept


def parse(text: str) -> List[Sighting]:
    """Parse either format — pick by what the text looks like."""
    if "lladdr" in text or " dev " in text:
        return parse_ip_neigh(text)
    return parse_arp_a(text)


def raw_pairs(text: str) -> List[Sighting]:
    """Every (ip, mac) the cache holds — NOT de-duped.

    The census de-dupes per MAC for a clean device list, but that erases
    the exact signal an ARP-spoof detector needs: one MAC on many IPs, or
    one IP flipping MACs. The anomaly watch (G3) reads this instead, so a
    duplicate is preserved rather than collapsed away.
    """
    if "lladdr" in text or " dev " in text:
        out = []
        for line in (text or "").splitlines():
            m = _IP_NEIGH.match(line.strip())
            if not m or not m.group("mac"):
                continue
            if (m.group("state") or "") in _DEAD_STATES:
                continue
            out.append(_build(m.group("ip"), m.group("mac")))
        return out
    out = []
    for line in (text or "").splitlines():
        m = _ARP_A.match(line)
        if not m:
            continue
        mac = m.group("mac")
        if mac.replace("-", ":").lower() == "ff:ff:ff:ff:ff:ff":
            continue
        out.append(_build(m.group("ip"), mac))
    return out


class LanCensusEngine:
    """Reads the LAN neighbour cache. Observes only."""

    name = NAME

    def __init__(self, command: Optional[list] = None):
        self._command = command  # injectable for tests

    def command(self) -> list:
        return list(self._command) if self._command else neighbour_command()

    def is_available(self) -> bool:
        """Whether the neighbour tool answers — run it, don't guess.

        Presence is not capability: the same lesson the connections engine
        paid for. A tool that is installed but blocked still can't census.
        """
        try:
            return self.run(timeout=10).exit_code == 0
        except Exception:  # noqa: BLE001
            return False

    def run(self, timeout: int = LIST_TIMEOUT) -> EngineOutput:
        """List the neighbour cache. Raw text; the domain reads it."""
        return run_command(
            engine=NAME,
            command=self.command(),
            timeout=timeout or DEFAULT_TIMEOUT,
            parse_json=False,
        )

    def sightings(self, timeout: int = LIST_TIMEOUT) -> List[Sighting]:
        """Convenience: run and parse in one call."""
        output = self.run(timeout=timeout)
        return parse(str(output.payload or ""))
