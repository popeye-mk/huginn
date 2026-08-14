"""Persistent findings history — the platform's own memory.

**Deliberately separate from the predecessor project's memory store.** Her `memory.json`
holds 8 learned facts and 2,043 chunks of ingested reference material.
Findings are a third kind of thing entirely: machine-generated,
timestamped, and unbounded — every triage run produces more. Writing
them into the same store would bury the 8 irreplaceable facts under
operational exhaust, and put "what broke last week" in competition with
Windows Server coursework.

So this owns its own file and its own FAISS index. the predecessor project's data is never
modified.

**Occurrences, not appends.** Running triage fifty times must not create
fifty copies of the same finding. Records are keyed by machine + finding
id; a repeat updates `last_seen` and increments `times_seen`. That
turns history into something worth having: *"disk_free_critical on
web-02, seen 14 times, first three weeks ago"* is institutional
knowledge. A list of 700 identical rows is not.

**The embedder is injected.** Semantic recall needs a model that lives
in the the predecessor project fork, but storing and reading findings must not. Passing it
in keeps this layer testable with no ML stack installed, and keeps the
store usable when the model is absent — it degrades to exact lookup and
says so, rather than failing.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from contracts import Correlation, Finding

SCHEMA_VERSION = "0.1.0"

NS_FINDING = "finding"
NS_CORRELATION = "correlation"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_key(namespace: str, machine_id: str, record_id: str) -> str:
    """Stable identity for a record. Repeats of the same thing collide."""
    return f"{namespace}:{machine_id}:{record_id}"


@dataclass
class StoredRecord:
    """One finding or correlation, with its history."""

    key: str
    namespace: str
    machine_id: str
    record_id: str
    text: str
    severity: str
    confidence: str
    first_seen: str
    last_seen: str
    times_seen: int = 1
    tags: tuple = ()
    suggested_action: Optional[str] = None
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        data["tags"] = list(self.tags)
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "StoredRecord":
        data = dict(data)
        data.pop("schema_version", None)
        data["tags"] = tuple(data.get("tags") or ())
        return cls(**data)

    @property
    def is_recurring(self) -> bool:
        """Seen more than once — the useful signal in operational history."""
        return self.times_seen > 1


@dataclass
class RecordReport:
    """What a `record()` call actually changed."""

    added: int = 0
    updated: int = 0
    skipped: int = 0
    keys: List[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return self.added + self.updated


class FindingsStore:
    """Findings and correlations, with occurrence history and recall."""

    def __init__(
        self,
        path: Path,
        embedder: Optional[Callable[[List[str]], Any]] = None,
        index_path: Optional[Path] = None,
    ):
        self.path = Path(path)
        self.index_path = Path(index_path) if index_path else (
            self.path.with_name("findings_index.faiss")
        )
        self.embedder = embedder
        self._records: Dict[str, StoredRecord] = {}
        self._loaded = False

    # -- persistence -----------------------------------------------------

    def load(self) -> "FindingsStore":
        if not self.path.exists():
            self._records = {}
            self._loaded = True
            return self
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._records = {
            key: StoredRecord.from_dict(value) for key, value in raw.items()
        }
        self._loaded = True
        return self

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {k: r.to_dict() for k, r in self._records.items()}
        self.path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8"
        )

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # -- writing ---------------------------------------------------------

    def _upsert(self, record: StoredRecord) -> str:
        """Add, or update an existing record's history."""
        existing = self._records.get(record.key)
        if existing is None:
            self._records[record.key] = record
            return "added"

        existing.last_seen = record.last_seen
        existing.times_seen += 1
        # Keep the newest wording: a finding's message often carries the
        # current measurement ("4.0% free"), and the latest reading is
        # the useful one.
        existing.text = record.text
        existing.severity = record.severity
        existing.confidence = record.confidence
        existing.suggested_action = record.suggested_action
        return "updated"

    def record(
        self,
        findings: Optional[List[Finding]] = None,
        correlations: Optional[List[Correlation]] = None,
    ) -> RecordReport:
        """Persist findings and correlations, merging repeats."""
        self._ensure_loaded()
        report = RecordReport()
        seen = _now()

        for finding in findings or []:
            outcome = self._upsert(_from_finding(finding, seen))
            setattr(report, outcome, getattr(report, outcome) + 1)
            report.keys.append(
                record_key(NS_FINDING, finding.machine_id, finding.id)
            )

        for correlation in correlations or []:
            outcome = self._upsert(_from_correlation(correlation, seen))
            setattr(report, outcome, getattr(report, outcome) + 1)
            report.keys.append(
                record_key(NS_CORRELATION, correlation.machine_id, correlation.id)
            )

        self.save()
        return report

    # -- reading ---------------------------------------------------------

    def all(self) -> List[StoredRecord]:
        self._ensure_loaded()
        return list(self._records.values())

    def for_machine(self, machine_id: str) -> List[StoredRecord]:
        return [r for r in self.all() if r.machine_id == machine_id]

    def recurring(self, minimum: int = 2) -> List[StoredRecord]:
        """Findings seen repeatedly — the ones worth fixing properly."""
        return sorted(
            (r for r in self.all() if r.times_seen >= minimum),
            key=lambda r: -r.times_seen,
        )

    def security_records(self) -> List[StoredRecord]:
        return [r for r in self.all() if "security" in r.tags]

    def prune(self, older_than_days: int = 180, keep_recurring: bool = True,
              keep_security: bool = True, now: Optional[str] = None) -> List[str]:
        """Age out stale one-off records. Returns the keys removed (E2).

        Retention here is deliberately conservative, because history is the
        product: recall lines like "seen 9× on this machine since May" are only
        as good as what was kept. So this drops **only** records that are all
        three of: older than the cutoff, seen just once, and not security —
        i.e. a one-off that never recurred and no longer describes the machine.
        A recurring or security finding is kept forever by default.

        Nothing is written until `save()`; the caller decides. An unparseable
        timestamp keeps the record (a record we cannot date is not evidence
        that it is stale).
        """
        self._ensure_loaded()
        try:
            cutoff = datetime.fromisoformat(now or _now()) - timedelta(days=older_than_days)
        except ValueError:
            return []
        removed = []
        for key, record in list(self._records.items()):
            if keep_recurring and record.is_recurring:
                continue
            if keep_security and "security" in (record.tags or ()):
                continue
            try:
                seen = datetime.fromisoformat(record.last_seen)
            except (TypeError, ValueError):
                continue                      # undateable → keep
            if seen < cutoff:
                del self._records[key]
                removed.append(key)
        return removed

    @property
    def can_recall(self) -> bool:
        """Whether semantic recall is available.

        Exposed so callers can say "exact matches only" rather than
        silently returning worse results — the same honesty rule the
        memory backend follows.
        """
        return self.embedder is not None


def _from_finding(finding: Finding, seen: str) -> StoredRecord:
    return StoredRecord(
        key=record_key(NS_FINDING, finding.machine_id, finding.id),
        namespace=NS_FINDING,
        machine_id=finding.machine_id,
        record_id=finding.id,
        text=finding.for_display(),
        severity=finding.severity,
        confidence=finding.confidence,
        first_seen=seen,
        last_seen=seen,
        tags=tuple(finding.tags),
        suggested_action=finding.suggested_action,
    )


def _from_correlation(correlation: Correlation, seen: str) -> StoredRecord:
    tags = ["correlation"]
    if correlation.involves_security:
        tags.append("security")
    if correlation.is_cross_source:
        tags.append("cross-engine")

    return StoredRecord(
        key=record_key(NS_CORRELATION, correlation.machine_id, correlation.id),
        namespace=NS_CORRELATION,
        machine_id=correlation.machine_id,
        record_id=correlation.id,
        text=correlation.story,
        severity=correlation.severity,
        confidence=correlation.confidence,
        first_seen=seen,
        last_seen=seen,
        tags=tuple(tags),
        suggested_action=correlation.suggested_action,
    )
