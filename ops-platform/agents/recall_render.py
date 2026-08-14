"""Shared renderer for the `recall` section M2 attaches to a result.

Triage was the first verb to volunteer memory; `threat` is the second
(P1). Both attach the same recall structure via `recalling.attach_recall`,
so both must render it identically — one function, imported in both, so
the memory layer can never look one way in triage and another in threat.

Lives in `agents/`, NOT `skills/`, for a hard-won reason: the fork and
the platform both have a top-level `skills` package, and the fork's
bridge loads platform skill files by path precisely to avoid that name.
A `from skills...` import inside a platform skill re-introduces the
collision — under the bridge it binds `sys.modules['skills']` to the
platform's package and the fork's own skills become unimportable (found
2026-07-22 as a 202-error cascade in the fork suite). `agents` is unique
to the platform, so this import is unambiguous from both sides.

Silence is deliberate. When there was nothing to recall against (a verb
with no findings) the block renders NOTHING rather than a hollow "recall:
nothing" line — that line would imply memory was meaningfully consulted
when it never had a finding to consult it with. An empty result that
followed real findings still speaks, because "we looked and nothing
matched" is a fact worth stating; that distinction lives in
`recalling._build`, which only sets a note when findings were present.
"""

from typing import List


def render_recall(result: dict) -> List[str]:
    """Turn `result['recall']` into printable lines, or [] when silent."""
    recall = result.get("recall")
    if not recall:
        return []

    sections = recall.get("sections") or []
    note = recall.get("note") or ""

    if not sections:
        return ["  recall: " + note, ""] if note else []

    lines = ["  recall:"]
    for entry in sections:
        finding = entry.get("finding") or ""
        lines.append(f"   - {finding}")
        if entry.get("history"):
            lines.append(f"       history: {entry['history']}")
        if entry.get("course"):
            lines.append(f"       course:  {entry['course']}")
    if note:
        lines.append(f"  ({note})")
    lines.append("")
    return lines
