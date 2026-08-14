"""Device persistence — the only module that touches devices.db.

Two things live here and nowhere else: the SQL, and the snapshot files.
Keeping them in one module means the storage format can change without
anything above noticing, and it is the rule the architecture test
enforces.

**Snapshots are files, device state is a row.** The snapshot JSON from an
engine is large, append-only, and occasionally useful in full; the
current state of a machine is small and constantly overwritten. Putting
snapshots in the database would make it grow without bound for data that
is almost always read as "the latest one". Files on disk, pointer in the
row.

**A device row never claims more than it knows.** `last_score` is
nullable and always stored beside its coverage. A score of 100 recorded
without "3 of 9 checked" is the fleet view's version of the lie this
platform exists to prevent — one green row hiding a machine nobody
actually examined.
"""

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from contracts import Device, DeviceHealth

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    device_id        TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL,
    os_family        TEXT NOT NULL DEFAULT 'unknown',
    discovery_source TEXT NOT NULL DEFAULT 'scan',
    first_seen       TEXT NOT NULL,
    last_seen        TEXT,
    last_score       INTEGER,
    last_checked     INTEGER,
    last_total       INTEGER,
    last_snapshot    TEXT
);
"""


# How many snapshots to keep per device. Triage runs every ~3h, so an
# unbounded history would grow forever — and worse, fleet correlation loads
# *every* snapshot, so stale copies of the same machine would pile up in the
# correlation input, not just on disk. Ten is ~30h of history at that cadence:
# enough to see a recent trend, bounded enough that correlation stays about
# "the latest state of each machine." One number to change if you want more.
DEFAULT_SNAPSHOT_KEEP = 10


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DeviceRepository:
    """Devices, their latest health, and their snapshot history."""

    def __init__(self, db_path: Path, snapshot_dir: Optional[Path] = None,
                 snapshot_keep: int = DEFAULT_SNAPSHOT_KEEP):
        self.db_path = Path(db_path)
        self.snapshot_dir = Path(
            snapshot_dir or self.db_path.with_name("snapshots")
        )
        self.snapshot_keep = max(1, int(snapshot_keep))
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    # -- writing ---------------------------------------------------------

    def upsert(self, device: Device) -> None:
        """Record a device, preserving `first_seen` on repeat sightings."""
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO devices
                    (device_id, hostname, os_family, discovery_source,
                     first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname   = excluded.hostname,
                    os_family  = excluded.os_family,
                    last_seen  = excluded.last_seen
                """,
                (
                    device.device_id, device.hostname, device.os_family,
                    device.discovery_source, device.first_seen, _now(),
                ),
            )
            conn.commit()

    def record_health(self, health: DeviceHealth) -> None:
        """Store a score together with the coverage it was measured over.

        Coverage is written in the same statement as the score, so the
        two cannot drift apart. A fleet row showing a number without
        knowing how much was checked is exactly the false confidence the
        platform is built to refuse.
        """
        with closing(self._connect()) as conn:
            conn.execute(
                """
                UPDATE devices
                   SET last_score = ?, last_checked = ?, last_total = ?,
                       last_seen = ?
                 WHERE device_id = ?
                """,
                (
                    health.score, health.checked, health.total,
                    _now(), health.device_id,
                ),
            )
            conn.commit()

    def save_snapshot(self, device_id: str, payload: dict) -> Path:
        """Write an engine snapshot to disk and point the device row at it."""
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        directory = self.snapshot_dir / device_id
        directory.mkdir(parents=True, exist_ok=True)

        path = directory / f"{stamp}.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        self._prune_snapshots(device_id)

        with closing(self._connect()) as conn:
            conn.execute(
                "UPDATE devices SET last_snapshot = ? WHERE device_id = ?",
                (str(path), device_id),
            )
            conn.commit()
        return path

    def _prune_snapshots(self, device_id: str) -> int:
        """Keep only the newest `snapshot_keep` snapshots for a device.

        Runs on every save, so history stays bounded on its own under the
        3-hourly triage — no separate cleanup job to remember. Timestamp
        filenames sort chronologically, so the oldest are simply the front of
        the list. The just-written file (and the row's `last_snapshot`) is
        always among those kept. Returns the number deleted. A file that
        cannot be removed is skipped, never fatal."""
        directory = self.snapshot_dir / device_id
        if not directory.exists():
            return 0
        files = sorted(directory.glob("*.json"))   # oldest first
        excess = len(files) - self.snapshot_keep
        removed = 0
        for old in files[:max(0, excess)]:
            try:
                old.unlink()
                removed += 1
            except OSError:
                pass
        return removed

    # -- reading ---------------------------------------------------------

    def all_devices(self) -> List[Device]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT * FROM devices ORDER BY hostname"
            ).fetchall()
        return [_device_from_row(r) for r in rows]

    def health_for(self, device_id: str) -> Optional[DeviceHealth]:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()

        if row is None or row["last_score"] is None:
            return None
        return DeviceHealth(
            device_id=row["device_id"],
            score=row["last_score"],
            checked=row["last_checked"] or 0,
            total=row["last_total"] or 0,
            assessed_at=row["last_seen"] or _now(),
        )

    def snapshot_paths(self, device_id: Optional[str] = None) -> List[Path]:
        """Snapshot files, newest last. Used by fleet correlation."""
        root = self.snapshot_dir / device_id if device_id else self.snapshot_dir
        if not root.exists():
            return []
        return sorted(root.rglob("*.json"))

    def count(self) -> int:
        with closing(self._connect()) as conn:
            return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


def _device_from_row(row: sqlite3.Row) -> Device:
    return Device(
        device_id=row["device_id"],
        hostname=row["hostname"],
        os_family=row["os_family"],
        discovery_source=row["discovery_source"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
    )
