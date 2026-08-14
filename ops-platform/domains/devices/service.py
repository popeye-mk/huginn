"""Devices domain — the fleet view.

Where the platform stops being about *this* machine.

**Correlation and scoring are Diagnostic Companion's `fleet.py`, not a
reimplementation.** It already groups findings across machines with an
honest denominator ("6 affected, of 9 checked, 2 excluded") and produces
an explainable score that is 100 minus a listed set of deductions. Both
are exactly right and already tested; writing a second version would
mean two answers to the same question and no reason to trust either.

It is imported rather than shelled out to — it is a pure Python module
with no side effects, so the engine layer's subprocess rule does not
apply. The install path comes from the engine, which is the module that
already knows where Diagnostic Companion lives.
"""

import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from contracts import Device, DeviceHealth
from domains.devices.repository import DeviceRepository
from engines.diagnostic_companion import DiagnosticCompanionEngine


@dataclass
class FleetView:
    """Every known device, with what is true across them."""

    devices: List[Device] = field(default_factory=list)
    health: Dict[str, DeviceHealth] = field(default_factory=dict)
    shared_findings: List[dict] = field(default_factory=list)
    snapshots_read: int = 0
    fleet_available: bool = True
    unavailable_reason: str = ""

    @property
    def total(self) -> int:
        return len(self.devices)

    @property
    def unassessed(self) -> List[Device]:
        """Devices with no health score.

        Listed separately rather than shown as 0 or 100. A machine nobody
        has checked is not a healthy machine and not a broken one — it is
        an unknown, and the fleet view says so.
        """
        return [d for d in self.devices if d.device_id not in self.health]

    @property
    def untrustworthy(self) -> List[DeviceHealth]:
        """Scores measured over incomplete data."""
        return [h for h in self.health.values() if not h.is_trustworthy]

    @property
    def environment_level(self) -> List[dict]:
        """Findings that look like the environment, not the machines.

        Six machines failing DNS at 09:02 is one broken resolver, not six
        broken machines. `fleet.py` flags these; surfacing them separately
        is the difference between one ticket and six.
        """
        return [f for f in self.shared_findings if f.get("environment_level")]


class DeviceService:
    """Fleet inventory, health and cross-machine correlation."""

    def __init__(
        self,
        repository: DeviceRepository,
        engine: Optional[DiagnosticCompanionEngine] = None,
    ):
        self.repository = repository
        self.engine = engine or DiagnosticCompanionEngine()

    # -- recording -------------------------------------------------------

    def record_scan(
        self,
        hostname: str,
        os_family: str,
        snapshot: dict,
        health_score: Optional[dict] = None,
    ) -> Device:
        """Register a machine and persist what this scan found.

        `snapshot` must be the *inner* snapshot — the object carrying
        `sections` — not the engine's full payload. `fleet.load_snapshots`
        silently skips anything without a `sections` key, so passing the
        wrapper produces an empty fleet view with no error at all. Caught
        exactly that way during R6.

        `device_id` is the hostname for now. That is wrong for a fleet
        where machines get renamed or reimaged, and it is recorded as a
        known limitation rather than papered over — a stable identifier
        needs something like a machine UUID, which neither engine
        currently reports.
        """
        device = Device(
            device_id=hostname, hostname=hostname, os_family=os_family
        )
        self.repository.upsert(device)

        if snapshot:
            if "sections" not in snapshot:
                raise ValueError(
                    "snapshot must contain 'sections' — pass the inner "
                    "snapshot, not the engine's full payload"
                )
            self.repository.save_snapshot(device.device_id, snapshot)

        if health_score and "score" in health_score:
            self.repository.record_health(
                DeviceHealth(
                    device_id=device.device_id,
                    score=int(health_score["score"]),
                    checked=int(health_score.get("checked", 0)),
                    total=int(health_score.get("total", 0)),
                )
            )
        return device

    # -- reading ---------------------------------------------------------

    def fleet(self) -> FleetView:
        """The whole estate: devices, health, and what they share."""
        devices = self.repository.all_devices()
        health = {}
        for device in devices:
            found = self.repository.health_for(device.device_id)
            if found is not None:
                health[device.device_id] = found

        shared, read, available, reason = self._correlate_snapshots()
        return FleetView(
            devices=devices,
            health=health,
            shared_findings=shared,
            snapshots_read=read,
            fleet_available=available,
            unavailable_reason=reason,
        )

    def _correlate_snapshots(self):
        """Run Diagnostic Companion's fleet correlation over stored scans."""
        paths = [str(p) for p in self.repository.snapshot_paths()]
        if not paths:
            return [], 0, True, ""

        fleet_module = self._load_fleet_module()
        if fleet_module is None:
            return (
                [], 0, False,
                "Diagnostic Companion's fleet module could not be imported",
            )

        try:
            snapshots = fleet_module.load_snapshots(paths)
            return fleet_module.correlate(snapshots), len(snapshots), True, ""
        except Exception as exc:  # noqa: BLE001 - report, never crash a view
            return [], 0, False, f"{type(exc).__name__}: {exc}"

    def _load_fleet_module(self):
        """Import `fleet.py` from the Diagnostic Companion install.

        Its modules import each other flatly (`from interpreter import
        evaluate`), so the install directory has to be on the path.
        """
        install = str(self.engine.install_path)
        if install not in sys.path:
            sys.path.insert(0, install)
        try:
            import fleet  # noqa: WPS433

            return fleet
        except Exception:  # noqa: BLE001
            return None
