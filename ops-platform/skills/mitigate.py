"""`mitigate` skill — turn confirmed findings into fixes you run (G6).

Runs one guard patrol, then for every confirmed finding prints the exact,
copy-pasteable mitigation with a plain reason. It is the "protect" step —
but protection stays in the operator's hands: **this skill executes
nothing.** It gathers findings and formats advice. Every fix is labelled as
something the operator runs by hand; the guard never touches traffic.

If a patrol can't run it says so honestly, and if nothing is wrong it says
there's nothing to mitigate — not a false all-clear, just no confirmed
finding to act on right now.
"""

from typing import Any

from domains.mitigation import mitigations_for
from platform_support import hostname
from agents.patrolling import run_patrol


def _render(mitigations, machine_id, checked) -> str:
    lines = ["  NETWORK GUARD — RECOMMENDED MITIGATIONS", "  " + "=" * 58,
             "  the predecessor project recommends; you decide and run. Nothing here is applied",
             "  automatically — the guard never touches your network.", ""]
    if not mitigations:
        lines.append("  No confirmed findings to mitigate right now.")
        lines.append("  (Checked " + str(checked) + " finding(s); a quiet "
                     "result is not a guarantee of safety.)")
        return "\n".join(lines)

    lines.append(f"  {len(mitigations)} recommended fix(es):")
    lines.append("")
    for m in mitigations:
        lines.append(m.as_text())
        lines.append("")
    lines.append("  Review each before running. If an exposure is expected "
                 "(e.g. your")
    lines.append("  router's own admin page), accept it instead: `ack <ip> "
                 "<port>`.")
    return "\n".join(lines)


def skill_mitigate(args: str, speaker: Any = None) -> str:
    """Recommend copy-pasteable fixes for confirmed findings. Never executes."""
    del args, speaker
    machine_id = hostname()
    result = run_patrol(machine_id)
    if result is None:
        return ("Could not read the LAN, so there is nothing to mitigate yet "
                "(the neighbour/ARP tool did not answer). Not an all-clear.")
    mitigations = mitigations_for(result.all_findings)
    return _render(mitigations, machine_id, len(result.all_findings))


def register(registry) -> None:
    registry.register(
        "mitigate",
        skill_mitigate,
        aliases=[
            "mitigation", "recommend fix", "how to fix", "block advice",
            "harden",
            "beveiligingsadvies",                         # NL
            "conseil de sécurité",                        # FR
        ],
    )
