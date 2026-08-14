"""Device identity and state — pure data.

A device is the thing findings attach to. Deliberately thin: this is an
ops platform, not a CMDB, and the design doc is explicit that competing
with Snipe-IT/GLPI is a losing move. What it holds is the minimum needed
to answer "is everything OK across the machines I look after".
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

CONTRACT_VERSION = "0.1.0"

# How a device came to be known about. An agentless platform learns of
# machines in different ways, and the difference matters when reading a
# fleet view: a device seen once from a USB stick is not the same kind of
# knowledge as one that reports in regularly.
DISCOVERY_SOURCES = ("scan", "manual", "imported")


@dataclass
class Device:
    """One machine the platform knows about."""

    device_id: str
    hostname: str
    os_family: str = "unknown"          # "windows" | "linux" | "unknown"
    discovery_source: str = "scan"
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: Optional[str] = None
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self):
        if not self.device_id:
            raise ValueError("device_id is required")
        if not self.hostname:
            raise ValueError("hostname is required")
        if self.discovery_source not in DISCOVERY_SOURCES:
            raise ValueError(
                f"unknown discovery_source: {self.discovery_source!r} "
                f"(expected one of {DISCOVERY_SOURCES})"
            )

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Device":
        data = dict(data)
        data.pop("contract_version", None)
        return cls(**data)


@dataclass
class DeviceHealth:
    """A device's health at a point in time.

    `score` is meaningless without `coverage` — a 100 over three of nine
    checks is not a healthy machine, it is an unexamined one. The two
    always travel together, and `is_trustworthy` exists so callers must
    confront that rather than reading the number alone.
    """

    device_id: str
    score: int
    checked: int
    total: int
    assessed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self):
        if not 0 <= self.score <= 100:
            raise ValueError(f"score out of range: {self.score}")
        if self.checked > self.total:
            raise ValueError(
                f"checked ({self.checked}) exceeds total ({self.total})"
            )

    @property
    def is_trustworthy(self) -> bool:
        """Whether this score rests on complete data."""
        return self.total > 0 and self.checked == self.total

    @property
    def coverage_label(self) -> str:
        return f"{self.checked}/{self.total} checked"

    def __str__(self) -> str:
        return f"{self.score} · {self.coverage_label}"

    def to_dict(self) -> dict:
        return asdict(self)
