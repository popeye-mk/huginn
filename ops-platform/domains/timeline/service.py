"""Guard timeline domain — what CHANGED on the LAN over time (G7).

The census/exposure/anomaly baselines answer "what is true now." They do
not answer "what changed this week," because a baseline is overwritten in
place. This domain keeps the missing axis: an append-only journal of the
guard's change-findings, written by each patrol pass, and a summariser that
folds it into "here is what moved, and when."

Two disciplines carry over:

- **Only changes, never steady state.** A port that has been open for a
  month is not news every 3 hours; recording it each patrol would bury the
  one device that appeared overnight. `_is_change` drops standing exposures
  and keeps the transitions — a new device, a moved IP, a device that left,
  a *newly* opened port, a live anomaly.
- **Collapse the repeats at read time.** A device that stays gone, or an
  anomaly that stays live, re-fires every patrol. The summary groups by
  finding id and shows each change once, with first-seen, last-seen and a
  count — so an ongoing problem reads as "since Tuesday, 14×," not fourteen
  identical lines.

Empty is not calm: a window with no recorded changes says so plainly, and
a journal that was never written says the patrol has not run — never "the
LAN was quiet."
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

# Keep the journal bounded — it is machine-local runtime state, appended to
# every ~3h forever. A few thousand lines is months of history at that
# cadence; older than that is not "this week," which is what the view is for.
MAX_JOURNAL_LINES = 4000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_change(finding) -> bool:
    """Whether a finding represents a change worth a place in the timeline.

    Standing open ports are current-state, not news — they would flood the
    journal every patrol. Everything else the guard produces is a transition:
    a new/moved/vanished device, a NEWLY-opened port, or a live anomaly."""
    tags = finding.tags or ()
    if "exposure" in tags and "NEWLY" not in (finding.message or ""):
        return False
    return True


def append_events(path: str, findings, machine_id: str, now: Optional[str] = None,
                  max_lines: int = MAX_JOURNAL_LINES) -> int:
    """Append this patrol's change-findings to the journal. Returns the count.

    Idempotent within a run only in the trivial sense — repeats across runs
    are expected and collapsed at read time. Bounded: the journal is trimmed
    to the newest `max_lines` after each append."""
    now = now or _now()
    events = [
        {"ts": now, "machine": machine_id, "id": f.id,
         "severity": f.severity, "message": f.message}
        for f in (findings or []) if _is_change(f)
    ]
    if not events:
        return 0

    os.makedirs(os.path.dirname(path), exist_ok=True)
    existing: List[str] = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            existing = fh.read().splitlines()
    lines = existing + [json.dumps(e, ensure_ascii=False) for e in events]
    lines = lines[-max_lines:]                      # keep the newest
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    return len(events)


@dataclass
class Change:
    """One distinct change, with how long it has been showing up."""

    id: str
    severity: str
    message: str
    first_ts: str
    last_ts: str
    count: int


@dataclass
class TimelineSummary:
    changes: List[Change] = field(default_factory=list)
    since_days: int = 7
    total_events: int = 0
    has_history: bool = False           # False = the journal was never written

    #: Oldest event still in the journal, and whether the journal is full.
    #:
    #: The journal trims to MAX_JOURNAL_LINES on every write, silently. Ask
    #: for 30 days of history on a full journal that only reaches back 9 and
    #: you get a confident answer about a window that does not exist —
    #: "3 changes in the last 30 days" when the other 21 days were dropped.
    #: A quietly shortened window is a small version of the same lie this
    #: whole project refuses, so `truncated` makes it sayable.
    oldest_ts: str = ""
    at_capacity: bool = False

    @property
    def truncated(self) -> bool:
        """Whether the asked-for window is longer than the history retained.

        Deliberately errs toward claiming truncation: `at_capacity` is a
        line count, so a journal that happens to hold exactly
        MAX_JOURNAL_LINES reports as truncated even if nothing was dropped.
        Over-warning costs a sentence; under-warning invents history.
        """
        return bool(self.at_capacity and self.oldest_ts)


def _load(path: str):
    if not os.path.exists(path):
        return None
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue                # a torn line never sinks the read
    return out


def summarize(path: str, since_days: int = 7, now: Optional[str] = None) -> TimelineSummary:
    """Fold the journal into distinct changes within the window, newest first."""
    records = _load(path)
    if records is None:
        return TimelineSummary(since_days=since_days, has_history=False)

    now_dt = datetime.fromisoformat(now) if now else datetime.now(timezone.utc)
    cutoff = now_dt - timedelta(days=since_days)

    grouped = {}
    total = 0
    for r in records:
        ts = r.get("ts", "")
        try:
            when = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if when < cutoff:
            continue
        total += 1
        key = r.get("id", "")
        g = grouped.get(key)
        if g is None:
            grouped[key] = {
                "id": key, "severity": r.get("severity", "info"),
                "message": r.get("message", ""), "first_ts": ts,
                "last_ts": ts, "count": 1,
            }
        else:
            g["count"] += 1
            if ts < g["first_ts"]:
                g["first_ts"] = ts
            if ts > g["last_ts"]:
                g["last_ts"] = ts

    changes = [Change(**g) for g in grouped.values()]
    changes.sort(key=lambda c: c.last_ts, reverse=True)     # most recent first
    stamps = [r.get("ts", "") for r in records if r.get("ts")]
    return TimelineSummary(changes=changes, since_days=since_days,
                           total_events=total, has_history=True,
                           oldest_ts=min(stamps) if stamps else "",
                           at_capacity=len(records) >= MAX_JOURNAL_LINES)


# --- triage of NEW journal events, for the scheduled patrol wrapper -------

@dataclass
class EventTriage:
    """How a batch of new journal events should be reported to a human.

    Separated from `_is_change` on purpose: earning a journal line and
    earning the operator's attention are different bars, and the scheduled
    wrapper's first version conflated them. A phone leaving the network is a
    real change, correctly recorded at `info` — and equally correctly not
    worth a 3am notification. Eleven of those in one pass looked like an
    incident until this split existed.
    """

    notable: List[dict] = field(default_factory=list)
    routine: int = 0
    unreadable: int = 0

    @property
    def should_report(self) -> bool:
        """Whether a human should be told. Unreadable lines count: a line we
        could not parse is not a line we can call harmless."""
        return bool(self.notable) or self.unreadable > 0


#: Severities treated as routine background churn. Everything else — including
#: any severity not listed here — is surfaced. Unknown must fail loud: a new
#: severity string added upstream should start by being noticed, not silently
#: filed under "normal".
ROUTINE_SEVERITIES = frozenset({"info"})


def triage_events(lines) -> EventTriage:
    """Split raw journal lines into notable / routine / unreadable.

    Pure: takes strings, returns a verdict, touches nothing. `lines` is any
    iterable of JSON-lines strings — normally the tail of the guard journal
    written during one patrol pass.
    """
    out = EventTriage()
    for line in lines:
        line = (line or "").strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            out.unreadable += 1          # never silently dropped
            continue
        if not isinstance(event, dict):
            out.unreadable += 1
            continue
        # strip() as well as lower(): stray whitespace is formatting noise,
        # not meaning, and surfacing " info " as an unknown severity would
        # produce a false alarm on every pass — the alarm fatigue this split
        # exists to prevent. An unknown VALUE still fails loud; an unknown
        # amount of padding does not.
        severity = str(event.get("severity") or "").strip().lower()
        if severity in ROUTINE_SEVERITIES:
            out.routine += 1
        else:
            out.notable.append(event)
    return out
