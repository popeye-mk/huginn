"""`history` skill — what has been seen on this machine before.

The verb that makes accumulated findings useful. A platform that records
history but cannot answer questions about it has a log file, not a
knowledge base.

Recall reports its own method: if the embedding model is unavailable the
answer says it fell back to substring matching, rather than returning
weaker results that look identical to strong ones.
"""

from typing import Any

from agents.instance import get_agent


def skill_history(args: str, speaker: Any = None) -> str:
    """Recall past findings, and name what keeps recurring."""
    del speaker
    result = get_agent().history(args or "")
    if not result.get("ok"):
        return str(result.get("body") or "History lookup did not complete.")

    recall_result = result.get("recall")
    recurring = result.get("recurring") or []
    lines = []

    if recall_result is not None and recall_result.hits:
        lines.append("Related to what you asked:")
        for hit in recall_result.hits:
            record = hit.record
            lines.append(
                f"  {hit.score:.2f}  [{record.severity}] {record.record_id}"
                f"  (seen {record.times_seen}x)"
            )
            lines.append(f"        {record.text[:110]}")
        lines.append("")

    if recurring:
        lines.append("Recurring on this machine:")
        for record in recurring[:5]:
            lines.append(
                f"  x{record.times_seen}  [{record.severity}] {record.record_id}"
            )
        lines.append("")

    if not lines:
        return (
            "Nothing recorded yet. Run `triage` first — history is built "
            "from what the engines find."
        )

    if recall_result is not None:
        lines.append(recall_result.summary)
    return "\n".join(lines)


def register(registry) -> None:
    """Registered natively as of 2026-07-27 — see the note in skills/backup.py.

    Reached through the archived fork's router until then, and silently
    absent from the native shell afterwards.
    """
    registry.register(
        "history",
        skill_history,
        aliases=[
            "seen before", "past findings", "recurring", "have we seen this",
            "geschiedenis", "eerder gezien",               # NL
            "historique", "déjà vu",                       # FR
        ],
    )
