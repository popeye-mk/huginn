"""Proactive recall — memory speaks during triage without being asked.

M2 of MEMORY-PLAN.md. Until now the findings store and the course
corpus only answered the explicit `history` verb; the point of having
them is that they volunteer: *this machine had this finding before* and
*the operator's own course material covers this topic*.

Grounding rules, inherited from R5 and non-negotiable here:

- a past-occurrence line appears only when the store actually holds the
  same finding for the same machine, and it carries the count and date
- a course-note line appears only with a real chunk to cite, and it
  names the document
- when there is nothing to say, the recall section SAYS there is
  nothing to say — one honest line, because absent recall and empty
  recall are different facts and the report must show which
"""

from __future__ import annotations

from typing import Dict, List

# How much of a cited chunk the report shows. Enough to be useful,
# short enough that the citation invites reading the source rather
# than replacing it.
SNIPPET_CHARS = 220

# Findings worth recalling against — the ones the operator will read.
MAX_RECALLED_FINDINGS = 3


def attach_recall(result: Dict[str, object], store, corpus=None) -> Dict[str, object]:
    """Add a `recall` section to a result, in place — OPERATIONAL history only.

    Course-note recall was removed 2026-07-26 with the rest of the answering
    path: Huginn reports what she measured, and "you have notes on this" is
    a knowledge feature, not an ops one. What remains is the history that IS
    ops evidence — "this finding was seen 9x on this machine since May".
    `corpus` is accepted and ignored so existing callers keep working.

    Never raises and never blocks the verb: recall is a bonus layer, and a
    failure inside it must not cost the operator their findings.
    """
    del corpus
    try:
        result["recall"] = _build(result, store)
    except Exception as exc:  # noqa: BLE001
        result["recall"] = {
            "sections": [],
            "note": f"recall unavailable ({type(exc).__name__}: {exc})",
        }
    return result


def _build(result: Dict[str, object], store) -> Dict[str, object]:
    findings = list(result.get("findings") or [])[:MAX_RECALLED_FINDINGS]
    machine = str(result.get("machine_id") or "")
    sections: List[Dict[str, str]] = []

    for finding in findings:
        title = getattr(finding, "title", "") or getattr(finding, "id", "")
        entry: Dict[str, str] = {"finding": title}

        seen = _past_occurrences(store, machine, getattr(finding, "id", ""))
        if seen:
            entry["history"] = seen

        if len(entry) > 1:
            sections.append(entry)

    note = ""
    if findings and not sections:
        # Only speak the empty case when there were findings to check. A
        # verb with no findings (e.g. a clean backup) has nothing to
        # recall against, and saying "nothing matched" would imply memory
        # was consulted when it never had a finding to consult it with.
        note = "no past occurrences of these findings"

    return {"sections": sections, "note": note}


def _past_occurrences(store, machine_id: str, finding_id: str) -> str:
    """'Seen N times since DATE', or '' when this is genuinely new."""
    if store is None or not finding_id:
        return ""
    try:
        records = store.for_machine(machine_id)
    except Exception:  # noqa: BLE001
        return ""
    for record in records:
        if record.record_id == finding_id and record.is_recurring:
            date = str(record.first_seen)[:10]
            return f"seen {record.times_seen}x on this machine since {date}"
    return ""
