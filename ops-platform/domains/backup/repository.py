"""Persistence for restore verifications — the only module touching this DB.

Verifications are kept rather than overwritten. A single latest result
answers "did it work last night"; the history answers "has it *ever*
worked", "when did it stop", and "how long were we exposed" — which are
the questions asked after an incident, and the ones an insurer asks
before one.

Records are append-only for the same reason: a verification history that
can be quietly amended is not evidence.
"""

import json
import sqlite3
from pathlib import Path
from typing import List, Optional

from contracts import (
    RestoreVerification,
    VerificationCheck,
    VerificationDepth,
    VerificationStatus,
)
from contracts.errors import RepositoryError

SCHEMA = """
CREATE TABLE IF NOT EXISTS verifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id     TEXT NOT NULL,
    status        TEXT NOT NULL,
    depth         TEXT NOT NULL,
    repository    TEXT NOT NULL DEFAULT '',
    snapshot_id   TEXT NOT NULL DEFAULT '',
    checks_json   TEXT NOT NULL DEFAULT '[]',
    depth_limited_by TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    started_at    TEXT NOT NULL,
    duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_verifications_device
    ON verifications(device_id, started_at DESC);
"""


class VerificationRepository:
    """Stores and reads restore verification history."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _migrate(self) -> None:
        try:
            with self._connect() as connection:
                connection.executescript(SCHEMA)
        except sqlite3.Error as exc:
            raise RepositoryError(f"could not open {self.db_path}: {exc}") from exc

    # -- writing ---------------------------------------------------------

    def record(self, verification: RestoreVerification) -> None:
        """Append one verification. Never updates an earlier row."""
        try:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO verifications (device_id, status, depth, "
                    "repository, snapshot_id, checks_json, depth_limited_by, "
                    "error_message, started_at, duration_seconds) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    self._row(verification),
                )
        except sqlite3.Error as exc:
            raise RepositoryError(f"could not record verification: {exc}") from exc

    def _row(self, v: RestoreVerification) -> tuple:
        return (
            v.device_id, v.status.value, v.depth.value, v.repository,
            v.snapshot_id,
            json.dumps([c.to_dict() for c in v.checks]),
            v.depth_limited_by, v.error_message, v.started_at,
            v.duration_seconds,
        )

    # -- reading ---------------------------------------------------------

    def latest_for(self, device_id: str) -> Optional[RestoreVerification]:
        """Most recent verification for one machine, or None.

        None means *never verified*, and callers must render that
        differently from a pass. It is the state 82% of backup jobs are
        in, and showing it as blank is how it stays there.
        """
        rows = self._query(
            "SELECT * FROM verifications WHERE device_id = ? "
            "ORDER BY started_at DESC LIMIT 1",
            (device_id,),
        )
        return self._from_row(rows[0]) if rows else None

    def history_for(self, device_id: str, limit: int = 20) -> List[RestoreVerification]:
        return [
            self._from_row(row)
            for row in self._query(
                "SELECT * FROM verifications WHERE device_id = ? "
                "ORDER BY started_at DESC LIMIT ?",
                (device_id, limit),
            )
        ]

    def all_latest(self) -> List[RestoreVerification]:
        """One row per device: the newest verification each one has."""
        return [
            self._from_row(row)
            for row in self._query(
                "SELECT * FROM verifications WHERE id IN ("
                "  SELECT MAX(id) FROM verifications GROUP BY device_id"
                ") ORDER BY device_id"
            )
        ]

    def _query(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        try:
            with self._connect() as connection:
                return connection.execute(sql, params).fetchall()
        except sqlite3.Error as exc:
            raise RepositoryError(f"query failed: {exc}") from exc

    def _from_row(self, row: sqlite3.Row) -> RestoreVerification:
        return RestoreVerification(
            device_id=row["device_id"],
            status=VerificationStatus(row["status"]),
            depth=VerificationDepth(row["depth"]),
            repository=row["repository"],
            snapshot_id=row["snapshot_id"],
            checks=[
                VerificationCheck(**c) for c in json.loads(row["checks_json"])
            ],
            depth_limited_by=row["depth_limited_by"],
            error_message=row["error_message"],
            started_at=row["started_at"],
            duration_seconds=row["duration_seconds"],
        )
