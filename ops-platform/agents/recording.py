"""Persistence side-effects of answering a question.

Split out of `ops_agent` when adding the backup verb pushed that module
past the 400-line limit. The limit did its job: what was left behind is
routing and explanation, and what moved here is bookkeeping — two
different reasons to change, which is exactly the signal the rule exists
to catch.

**The invariant every function here holds: a failure to record must never
cost the user their result.** They asked a diagnostic question and the
answer already exists in memory. Losing it to a database error would be
the tool making the machine's problems worse, which is the one thing this
platform must not do.
"""

from typing import Optional, Tuple


def persist_triage(store, devices, gathered, triage) -> Tuple[Optional[object], str]:
    """Record a triage: the scan against its machine, then the findings.

    Returns the store's report and an error string. The error is
    returned rather than raised so the caller can show it *next to* the
    triage instead of in place of it.
    """
    try:
        record_scan(devices, gathered)
    except Exception:  # noqa: BLE001
        # Deliberately swallowed and not reported: the device row is
        # bookkeeping the user never asked for, and a warning about it
        # would sit above findings that actually matter.
        pass

    try:
        return store.record(triage.findings, triage.correlations), ""
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def record_scan(devices, gathered) -> None:
    """Persist this scan against the machine it came from.

    Uses the snapshot `gather` already collected rather than re-running
    the engine — bookkeeping should not double the cost of a triage.
    """
    if not gathered.snapshot:
        return
    devices.record_scan(
        hostname=gathered.machine_id,
        os_family=gathered.snapshot.get("os", "unknown"),
        snapshot=gathered.snapshot,
        health_score=gathered.health_score,
    )


def persist_verification(repository, verification) -> str:
    """Append a restore verification. Returns "" or why it failed.

    Failures, errors and NOT_ATTEMPTED are all recorded. A history that
    kept only successes could answer "has this ever worked" but never
    "when did it stop" — and after an incident, the second question is
    the one being asked.
    """
    try:
        repository.record(verification)
        return ""
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"


def verification_history(repository, machine: str, limit: int = 5) -> list:
    """Past verifications; an empty list is a meaningful answer, not an error."""
    try:
        return repository.history_for(machine, limit=limit)
    except Exception:  # noqa: BLE001
        return []
