"""Diagnostic Companion output → Finding contracts.

The mapping is nearly field-for-field, because the shared schema
deliberately adopted Diagnostic Companion's severity and confidence
vocabulary rather than inventing a parallel one. That decision pays off
here: there is no translation table to maintain and no semantics to
drift.

**No interpretation happens in this module.** Diagnostic Companion
already decides severity, confidence, root-cause chains and next steps,
and it does so better than a mapping layer could. Re-deriving any of it
would create a second source of truth for the same judgement.
"""

import sys
from typing import List, Optional

from contracts import Coverage, Finding, sort_findings

SOURCE = "diagnostic-companion"


def extract_coverage(payload: dict) -> Coverage:
    """Pull checked/total from the health score.

    Falls back to counting sections that ran, and to zero knowledge if
    even that is missing. **Never defaults to 'everything was checked'** —
    that would manufacture the exact false confidence both this platform
    and Diagnostic Companion exist to prevent.
    """
    score = payload.get("health_score") or {}
    if "checked" in score and "total" in score:
        return Coverage(checked=score["checked"], total=score["total"])

    sections = (payload.get("snapshot") or {}).get("sections") or {}
    if sections:
        ran = sum(1 for s in sections.values() if s.get("status") == "ok")
        return Coverage(checked=ran, total=len(sections))

    return Coverage(checked=0, total=0)


def extract_not_checked(payload: dict) -> List[tuple]:
    """Rebuild the list of collectors that could not run.

    Diagnostic Companion's JSON carries raw sections but not this derived
    list, while its HTML renderer needs it to show what was *not*
    checked. Reconstructed the way `interpreter.evaluate` does it: any
    section whose status is not "ok".

    Omitting this makes a report silently claim full coverage — a bug
    found during Milestone 1 and pinned by a test since.
    """
    sections = (payload.get("snapshot") or {}).get("sections") or {}
    return [
        (cid, sec.get("status"), sec.get("reason"))
        for cid, sec in sections.items()
        if sec.get("status") != "ok"
    ]


def to_findings(payload: dict, machine_id: Optional[str] = None) -> List[Finding]:
    """Map a Diagnostic Companion payload into Finding records.

    `findings` and `worth_checking` are merged into one list. Diagnostic
    Companion separates them so possible-confidence items cannot
    headline; the shared schema already enforces that as
    `Finding.can_headline`, so keeping two lists would duplicate a rule
    that lives in the contract.
    """
    snapshot = payload.get("snapshot") or {}
    machine = machine_id or snapshot.get("hostname") or "unknown"
    timestamp = snapshot.get("collected_at")
    coverage = extract_coverage(payload)

    findings = []
    raw_items = list(payload.get("findings") or []) + list(
        payload.get("worth_checking") or []
    )

    for raw in raw_items:
        try:
            findings.append(
                Finding(
                    id=raw["id"],
                    source_module=SOURCE,
                    machine_id=machine,
                    severity=raw["severity"],
                    confidence=raw["confidence"],
                    message=raw["finding"],
                    suggested_action=raw.get("next_step"),
                    coverage=coverage,
                    timestamp=timestamp,
                )
            )
        except (KeyError, ValueError) as exc:
            # Skipped loudly, never silently — dropping a finding without
            # a word would be its own small version of hiding a problem.
            print(
                f"  warning: skipped unmappable finding "
                f"{raw.get('id', '?')}: {exc}",
                file=sys.stderr,
            )

    return sort_findings(findings)
