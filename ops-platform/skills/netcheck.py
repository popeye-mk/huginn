"""`netcheck` and `security` skills — the predecessor project registration.

Thin, like `diagnose`: parse, delegate, format. Two verbs share this
module because they share one formatter and one service; splitting them
would duplicate the rendering without separating any decision.

Rendering prefers each finding's plain-language text where the source
provided one. netdiag writes `for_user` copy for someone who does not
know what a gateway is, and that is the audience the platform is for.
"""

from typing import Any, List

from agents.instance import get_agent
from agents.recall_render import render_recall
from contracts import Finding



def _render(result: dict, empty_message: str) -> str:
    lines = []

    headline = result.get("headline")
    if headline:
        lines += [headline, ""]

    findings: List[Finding] = result.get("findings") or []
    if not findings:
        lines.append(empty_message)
    else:
        for finding in findings:
            marker = "!" if finding.is_actionable else "-"
            lines.append(f" {marker} [{finding.severity}] {finding.for_display()}")
            if finding.suggested_action:
                lines.append(f"     → {finding.suggested_action}")

    # Memory volunteers (M5): a recurring finding here says so, with the
    # count and the operator's own course note — silent when nothing to add.
    lines += render_recall(result)

    # Gaps are stated even on an otherwise clean result. A network scan
    # that could not probe upstream has not cleared upstream.
    gaps = result.get("not_checked") or []
    unknown = result.get("unknown_segments") or []
    if gaps or unknown:
        lines.append("")
        if gaps:
            lines.append(f" {len(gaps)} check(s) could not run.")
        if unknown:
            lines.append(f" Not graded: {', '.join(unknown)}.")

    return "\n".join(lines)


def skill_netcheck(args: str, speaker: Any = None) -> str:
    """Check the network and name which segment is at fault."""
    del speaker
    result = get_agent().netcheck()
    if not result.get("ok"):
        return str(result.get("body") or "Network check did not complete.")
    return _render(result, "No network problems found in what could be checked.")


def skill_security(args: str, speaker: Any = None) -> str:
    """Report network security exposure on this machine."""
    del speaker
    result = get_agent().security()
    if not result.get("ok"):
        return str(result.get("body") or "Security check did not complete.")
    return _render(
        result,
        "No exposure found in what could be checked — this is not a "
        "clean bill of health.",
    )


def register(registry) -> None:
    """Register both verbs with the predecessor project's SkillRegistry."""
    registry.register(
        "netcheck",
        skill_netcheck,
        aliases=[
            "network", "check network", "internet",
            "netwerk", "controleer netwerk",          # NL
            "reseau", "vérifier réseau",               # FR
        ],
    )
    registry.register(
        "security",
        skill_security,
        aliases=[
            "exposure", "security check", "hygiene",
            "beveiliging",                              # NL
            "securite", "sécurité",                     # FR
        ],
    )
