"""Turning a result into a sentence a tired person can act on.

Extracted from `ops_agent` when the `threat` verb pushed it past the
400-line limit. Explanation and routing had been sharing a class because
both are "what the agent does", but they change for different reasons:
routing changes when a verb is added, explanation changes when the
wording is wrong. Only one of those happens at 2am.

**The rule this module exists to hold:** "no problems found" and "no
problems found in what could be checked" are different claims, and
conflating them is how a diagnostic tool loses trust. Every sentence
here that reports an absence also reports its coverage.
"""

from typing import Dict, List

from contracts import Finding


def explain(result: Dict[str, object]) -> str:
    """Plain-language summary of what happened."""
    if not result.get("ok"):
        return str(result.get("body") or "The ops action did not complete.")

    findings: List[Finding] = result.get("findings") or []
    gaps = result.get("not_checked") or []

    if not findings:
        return _nothing_found(gaps) + _recall_lines(result)
    return (_something_found(findings, gaps, result.get("headline"))
            + _recall_lines(result))


def _recall_lines(result) -> str:
    """Memory volunteering, one line per fact it can actually cite.

    M2's grounding rule rendered: history lines carry counts and dates,
    course lines carry a named document, and an empty recall still says
    so — because absent recall and empty recall are different facts.
    """
    recall = result.get("recall")
    if not isinstance(recall, dict):
        return ""
    lines = []
    for section in recall.get("sections") or []:
        finding = section.get("finding", "")
        if section.get("history"):
            lines.append(f"  recall: '{finding}' {section['history']}")
        if section.get("course"):
            lines.append(f"  course: {section['course']}")
    if not lines and recall.get("note"):
        lines.append(f"  recall: {recall['note']}")
    return ("\n" + "\n".join(lines)) if lines else ""


def _nothing_found(gaps) -> str:
    """An absence, always with its denominator attached."""
    if gaps:
        return (
            f"No problems found in what could be checked — "
            f"but {len(gaps)} check(s) could not run. "
            f"This is not a clean bill of health."
        )
    return "No problems found; all checks ran."


def _something_found(findings, gaps, headline) -> str:
    actionable = [f for f in findings if f.is_actionable]
    lead = headline or findings[0].message

    summary = f"{lead} ({len(findings)} finding(s)"
    if actionable:
        summary += f", {len(actionable)} needing action now"
    summary += ")"
    if gaps:
        summary += f". {len(gaps)} check(s) could not run."
    return summary
