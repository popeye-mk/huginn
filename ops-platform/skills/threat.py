"""`threat` skill — is this machine talking to somewhere it should not?

The output is built around one refusal: **a run that compared nothing
must never look like a run that found nothing.** So the feed status is
printed first, before any verdict, and the closing line always states
coverage rather than just an outcome.

The other deliberate choice is that a clean result is not celebrated.
"No matches" from a fresh feed against twelve connections is genuine
information; the same words from a feed nobody downloaded are not, and
the reader should be able to tell them apart at a glance.
"""

from typing import Any, List

from agents.instance import get_agent
from agents.recall_render import render_recall

_BAR = "=" * 66


def _render_feeds(result) -> List[str]:
    """Feed state first. It is the denominator for everything below."""
    lines = ["  Feeds", "  " + "-" * 64]
    for feed in result.feeds:
        lines.append(f"   {feed}: in use")
    for reason in result.unusable_feeds:
        lines.append(f"   {reason}")
    if not result.feeds and not result.unusable_feeds:
        lines.append("   none configured — run `python3 tools/update_feeds.py`")
    return lines


def _render_matches(result) -> List[str]:
    if not result.findings:
        return []
    lines = ["", "  Matches", "  " + "-" * 64]
    for finding in result.findings:
        lines.append(f"   [{finding.severity}/{finding.confidence}] {finding.message}")
        if finding.plain_message:
            lines.append(f"     {finding.plain_message}")
        if finding.suggested_action:
            lines.append(f"     -> {finding.suggested_action}")
        lines.append("")
    return lines


def skill_threat(args: str, speaker: Any = None) -> str:
    """Check outbound connections against downloaded threat feeds."""
    del speaker, args
    outcome = get_agent().threat_check()
    if not outcome.get("ok"):
        return str(outcome.get("body") or "The threat check did not run.")

    result = outcome["threat"]
    lines = [_BAR, "  OUTBOUND THREAT CHECK", _BAR, ""]
    lines += _render_feeds(result)
    lines += _render_matches(result)
    lines += render_recall(outcome)

    lines += ["", "  " + "-" * 64]
    lines.append(f"  Coverage: {result.coverage}")
    lines.append(f"  {result.summary}")

    if not result.checked_anything:
        # The distinction the whole domain exists to preserve, restated
        # where someone skimming will actually see it.
        lines.append(
            "  This is NOT a clean bill of health — nothing was compared."
        )
    elif result.had_nothing_to_check:
        lines.append(
            "  Nothing to check is not the same as nothing found: the feeds "
            "were ready and this machine had no external connections."
        )
    elif not result.findings:
        lines.append(
            "  Nothing matched. Note this only covers addresses the feeds "
            "know about; it is evidence, not a guarantee."
        )
    return "\n".join(lines)


def register(registry) -> None:
    """Registered natively as of 2026-07-27 — see the note in skills/backup.py.

    Reached through the archived fork's router until then, and silently
    absent from the native shell afterwards.
    """
    registry.register(
        "threat",
        skill_threat,
        aliases=[
            "threat check", "outbound check", "c2 check", "malware check",
            "dreiging", "uitgaande controle",              # NL
            "menace", "contrôle sortant",                  # FR
        ],
    )
