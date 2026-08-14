"""`harden` skill — what would let an attack succeed, before one does (H1).

Every other guard verb answers "is something happening?". This one answers the
question that comes first: **would it work if it were tried?** It reads four
standing facts about THIS host — its own listening ports, whether it answers
LLMNR, whether it accepts IPv6 router advertisements (the mitm6 precondition),
and whether a host firewall is active — and reports each as a condition to fix,
never as an attack in progress.

    harden

It is the honest form of prediction: not forecasting, but preconditions. A
reading that could not be taken is listed as unchecked, never as a pass.
"""

from typing import Any

from domains.posture import assess, unchecked
from engines.host_posture import read_posture
from platform_support import hostname


def _render(findings, missing, machine_id: str) -> str:
    lines = [f"  HOST POSTURE — {machine_id}", "  " + "=" * 58,
             "  What would let an attack work — not what is happening now.", ""]
    if findings:
        lines.append(f"  {len(findings)} condition(s) worth fixing:")
        for f in findings:
            lines.append(f"   ! [{f.severity}] {f.message}")
            if f.suggested_action:
                lines.append(f"       -> {f.suggested_action}")
    else:
        lines.append("  Nothing to fix in what could be read.")

    if missing:
        lines += ["", "  NOT CHECKED (not a clean bill of health):"]
        for item in missing:
            lines.append(f"   ? {item} — could not be read on this machine")
    return "\n".join(lines)


def skill_harden(args: str, speaker: Any = None) -> str:
    """Report the standing conditions that would let a LAN attack succeed."""
    del args, speaker
    machine_id = hostname()
    posture = read_posture()
    return _render(assess(posture, machine_id), unchecked(posture), machine_id)


def register(registry) -> None:
    registry.register(
        "harden",
        skill_harden,
        aliases=[
            "posture", "host posture", "hardening", "what would work",
            "preconditions", "attack surface",
            "verharden",                                    # NL
            "durcissement",                                 # FR
        ],
    )
