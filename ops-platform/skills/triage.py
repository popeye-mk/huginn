"""`triage` skill — run every engine and report shared root causes.

This is the platform's headline verb. The formatting decisions here are
the product, so they are deliberate:

**Stories lead, symptoms follow.** A correlated story is printed before
the individual findings, because "these four alerts are one problem" is
the sentence that changes what someone does next.

**Suppressed findings are labelled, not hidden.** When a story explains a
symptom away, that symptom moves under the story rather than vanishing.
A reader who cannot see the parts cannot check the reasoning, and a
correlation engine nobody can check is one nobody should trust.

**The report says which engines ran.** "No cross-signal stories found"
means nothing if only one engine reported — that is an untested claim,
not an all-clear, and it is printed as such.
"""

from typing import Any, List

from agents.instance import get_agent
from contracts import Correlation, Finding
from agents.recall_render import render_recall


_BAR = "=" * 66


def _render_correlation(index: int, corr: Correlation) -> List[str]:
    scope = "cross-engine" if corr.is_cross_source else "single-engine"
    marker = " [SECURITY]" if corr.involves_security else ""

    lines = [
        _BAR,
        f"  STORY {index}  [{corr.severity}/{corr.confidence}]"
        f"  {scope}{marker}",
        _BAR,
        f"  {corr.story}",
        "",
        f"  Explains: {', '.join(corr.member_ids)}",
        f"  Coverage: {corr.coverage}",
    ]
    if corr.suggested_action:
        lines += ["", f"  Do this: {corr.suggested_action}"]
    lines += _render_grounding(corr)
    lines.append("")
    return lines


def _render_grounding(corr: Correlation) -> List[str]:
    """Show what the story stands on — or state that it stands alone.

    Printed for both cases on purpose. A story with references and a
    story without them must not render identically, or the absence of
    grounding becomes invisible and the reader has no way to tell which
    conclusions they can go and check.
    """
    if corr.is_grounded:
        lines = ["", "  Based on:"]
        for citation in corr.citations:
            lines.append(f"   - {citation.label}")
        return lines
    return ["", f"  Not grounded: {corr.grounding}."]


def _render_findings(title: str, findings: List[Finding]) -> List[str]:
    if not findings:
        return []
    lines = [f"  {title}"]
    for f in findings:
        marker = "!" if f.is_actionable else "-"
        tag = " [security]" if f.is_security else ""
        lines.append(f"   {marker} [{f.severity}]{tag} {f.for_display()}")
    lines.append("")
    return lines


def _render_scope(result: dict) -> List[str]:
    ran = result.get("engines_run") or ()
    missing = result.get("engines_missing") or ()
    gaps = result.get("not_checked") or []

    lines = ["  " + "-" * 62, f"  Engines run: {', '.join(ran) or 'none'}"]
    if missing:
        lines.append(f"  Not available: {', '.join(missing)}")
    if gaps:
        lines.append(f"  {len(gaps)} individual check(s) could not run.")

    if len(ran) < 2:
        lines.append(
            "  Only one engine reported — cross-engine correlation was "
            "not tested for."
        )
    return lines


def skill_triage(args: str, speaker: Any = None) -> str:
    """Run all available engines and report correlated root causes."""
    del speaker
    result = get_agent().triage()
    if not result.get("ok"):
        return str(result.get("body") or "Triage did not complete.")

    correlations: List[Correlation] = result.get("correlations") or []
    standalone: List[Finding] = result.get("standalone") or []
    machine = result.get("machine_id", "unknown")

    lines = [f"  Triage — {machine}", ""]

    if correlations:
        for i, corr in enumerate(correlations, start=1):
            lines += _render_correlation(i, corr)
    else:
        lines += ["  No correlated stories found.", ""]

    lines += _render_findings(
        "Findings not explained by any story:", standalone
    )
    lines += render_recall(result)
    lines += _render_scope(result)
    return "\n".join(lines)


def register(registry) -> None:
    registry.register(
        "triage",
        skill_triage,
        aliases=[
            "correlate", "full check", "what is going on",
            "volledige controle",       # NL
            "analyse complete",         # FR
        ],
    )
