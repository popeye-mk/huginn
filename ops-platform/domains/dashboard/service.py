"""Dashboard domain — assemble the guard's current state (G5).

The pane of glass. It reads the state the guard verbs already persist — the
census baseline (who's on the LAN, with names) and the exposure baseline
(which ports each device leaves open) — and folds them into one plain dict
a view can render. It is **read-only**: it computes nothing new, sends
nothing, and touches no network. A snapshot, not a control panel.

The honesty rules carry over: an empty baseline is "no scan yet," not "the
LAN is clean," and a device with no open ports is "none seen," not "safe."
The view is expected to say so.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from engines.lan_exposure import DANGEROUS_PORTS

# Which open ports colour a device "hot" vs merely "warm" on the heatmap —
# mirrors the exposure domain's severity split.
_CRITICAL_PORTS = {21, 23, 139, 445}

# Device fingerprinting (G9) — a best-effort *type* from signals the guard
# already has (vendor OUI, resolved name, open ports), so "do I recognise this
# device?" reads as "printer" or "phone", not a bare MAC. A guess, never a
# verdict: unknown stays unknown rather than a confident wrong label.
_PRINTER_PORTS = {515, 631, 9100}
_NAS_PORTS = {548, 2049, 5000, 5001}
_COMPUTER_PORTS = {22, 139, 445, 3389, 5900}
_ROUTER_HINTS = ("avm", "fritz", "tp-link", "tplink", "netgear", "asus",
                 "ubiquiti", "unifi", "omada", "mikrotik", "zyxel", "draytek",
                 "router", "gateway", "repeater")
_NAS_HINTS = ("nas", "synology", "qnap", "fritz!nas")
_PRINTER_HINTS = ("printer", "laserjet", "officejet", "canon", "epson", "brother")
_IOT_HINTS = ("tuya", "espressif", "samjin", "sonoff", "shelly", "signify",
              "philips hue", "nest", "ring", "xiaomi", "sengled", "smart",
              "bulb", "plug", "sensor", "thermostat", "doorbell", "camera", "cam")
_PHONE_HINTS = ("iphone", "ipad", "android", "pixel", "galaxy", "phone", "tablet")
_COMPUTER_HINTS = ("pc", "desktop", "laptop", "macbook", "imac", "server", "aspire")


def classify_device(vendor: str, name: str, open_ports) -> str:
    """Best-effort device type from vendor + name + open ports. A guess."""
    ports = set(open_ports or [])
    text = f"{(vendor or '').lower()} {(name or '').lower()}"
    name_low = (name or "").lower()
    if ports & _PRINTER_PORTS or any(h in text for h in _PRINTER_HINTS):
        return "printer"
    if any(h in text for h in _ROUTER_HINTS):
        return "router"
    if ports & _NAS_PORTS or any(h in text for h in _NAS_HINTS):
        return "NAS"
    if "randomized" in (vendor or "").lower() or any(h in name_low for h in _PHONE_HINTS):
        return "phone / tablet"
    if any(h in text for h in _IOT_HINTS):
        return "IoT / smart-home"
    if ports & _COMPUTER_PORTS or any(h in name_low for h in _COMPUTER_HINTS):
        return "computer"
    return "unknown"


@dataclass
class DeviceRow:
    ip: str
    mac: str
    name: str
    vendor: str
    first_seen: str
    last_seen: str
    open_ports: List[int] = field(default_factory=list)

    @property
    def heat(self) -> str:
        if any(p in _CRITICAL_PORTS for p in self.open_ports):
            return "critical"
        if self.open_ports:
            return "warning"
        return "clear"

    @property
    def label(self) -> str:
        return self.name or self.vendor or "unknown"

    @property
    def device_type(self) -> str:
        """A best-effort fingerprint (G9): printer / router / phone / …"""
        return classify_device(self.vendor, self.name, self.open_ports)

    def as_dict(self) -> dict:
        return {
            "ip": self.ip, "mac": self.mac, "name": self.name,
            "vendor": self.vendor, "label": self.label,
            "device_type": self.device_type,
            "first_seen": self.first_seen, "last_seen": self.last_seen,
            "open_ports": self.open_ports,
            "port_names": [DANGEROUS_PORTS.get(p, str(p)) for p in self.open_ports],
            "heat": self.heat,
        }


@dataclass
class DashboardState:
    devices: List[DeviceRow] = field(default_factory=list)
    generated_at: str = ""
    machine_id: str = ""
    # G7 change-history folded in for the view (injected — the dashboard domain
    # does not read the timeline itself; the skill does and passes it here).
    recent_changes: List[dict] = field(default_factory=list)

    @property
    def device_count(self) -> int:
        return len(self.devices)

    @property
    def exposed_count(self) -> int:
        return sum(1 for d in self.devices if d.open_ports)

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.devices if d.heat == "critical")

    def as_dict(self) -> dict:
        return {
            "generated_at": self.generated_at,
            "machine_id": self.machine_id,
            "device_count": self.device_count,
            "exposed_count": self.exposed_count,
            "critical_count": self.critical_count,
            "devices": [d.as_dict() for d in self.devices],
            "recent_changes": self.recent_changes,
        }


def _sort_key(row: DeviceRow):
    # hottest first, then by IP's last octet so the list is stable
    rank = {"critical": 0, "warning": 1, "clear": 2}[row.heat]
    try:
        octet = int(row.ip.rsplit(".", 1)[-1])
    except ValueError:
        octet = 999
    return (rank, octet)


def build_state(census_baseline, exposure_baseline,
                machine_id="", generated_at="",
                recent_changes=None) -> DashboardState:
    """Fold the two baselines into one dashboard state, hottest device first.

    `recent_changes` is the G7 timeline (list of dicts) the caller already
    summarised — folded in for the view, not read here."""
    exposure_baseline = exposure_baseline or {}
    rows: List[DeviceRow] = []
    for mac, rec in (census_baseline or {}).items():
        ip = rec.get("ip", "")
        rows.append(DeviceRow(
            ip=ip, mac=mac,
            # A manual label (G1f) wins over the probed name (G1e).
            name=rec.get("label") or rec.get("name", ""),
            vendor=rec.get("vendor", ""),
            first_seen=rec.get("first_seen", ""),
            last_seen=rec.get("last_seen", ""),
            open_ports=sorted(exposure_baseline.get(ip, [])),
        ))
    rows.sort(key=_sort_key)
    return DashboardState(devices=rows, machine_id=machine_id,
                          generated_at=generated_at,
                          recent_changes=list(recent_changes or []))
