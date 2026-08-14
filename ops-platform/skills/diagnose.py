"""`diagnose` skill — the predecessor project registration.

Thin by design: parse, delegate, format. All judgement lives in
`domains/diagnostics/`. If an `if` about business meaning ever appears
here, it belongs one layer down.

Aliases cover EN/NL/FR to match the predecessor project's existing trilingual skill
convention.
"""

from typing import Any

from agents.instance import get_agent

SKILL_NAME = "diagnose"
ALIASES = (
    "healthcheck", "health check", "check this machine",
    "diagnostiek", "controleer machine",      # NL
    "diagnostic", "verifier machine",          # FR
)



def skill_diagnose(args: str, speaker: Any = None) -> str:
    """Run host diagnostics and return a plain-language summary."""
    del speaker  # formatting handled by the caller's renderer

    result = get_agent().diagnose()
    summary = get_agent().explain(result)

    findings = result.get("findings") or []
    if not findings:
        return summary

    lines = [summary, ""]
    for finding in findings:
        marker = "!" if finding.is_actionable else "-"
        lines.append(f" {marker} [{finding.severity}] {finding.message}")
        if finding.suggested_action:
            lines.append(f"     → {finding.suggested_action}")

    return "\n".join(lines)


def register(registry) -> None:
    """Register with the predecessor project's SkillRegistry."""
    registry.register(SKILL_NAME, skill_diagnose, aliases=list(ALIASES))
