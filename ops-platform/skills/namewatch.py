"""`namewatch` skill — catch an LLMNR/mDNS name-resolution poisoner (G8).

Sends a query for a name that cannot exist and reports anyone who answers.
On an honest LAN nothing replies; a reply is a Responder-style attacker
poisoning name resolution to steal Windows logins — one of the classic
switched-LAN attacks a joined host can see.

    namewatch          probe once and report

Active but standard, the operator's own LAN only (the same posture as the
exposure scan). Honest degrade: if the probe could not run it says so —
never folds a socket failure into "all clear."
"""

from typing import Any

from domains.spoofwatch import assess
from engines.lan_llmnr import available, probe, random_name
from platform_support import hostname


def _render(findings, machine_id: str, probed: bool) -> str:
    lines = [f"  NETWORK GUARD — NAME-POISONING WATCH ({machine_id})",
             "  " + "=" * 58]
    if not probed:
        lines.append("  Could not send the probe (no usable network socket).")
        lines.append("  Not checked — this is NOT a clean bill of health.")
        return "\n".join(lines)

    if not findings:
        lines.append("  No responder answered the decoy name.")
        lines.append("  (LLMNR, mDNS and NBT-NS probed; nothing claimed a name "
                     "that does not exist. A quiet probe is not a guarantee — "
                     "only that no poisoner replied in the window.)")
        return "\n".join(lines)

    for f in findings:
        lines.append(f"   ! [{f.severity}] {f.message}")
        if f.suggested_action:
            lines.append(f"       -> {f.suggested_action}")
    return "\n".join(lines)


def skill_namewatch(args: str, speaker: Any = None) -> str:
    """Probe for an LLMNR/mDNS poisoner and report any responder."""
    del args, speaker
    machine_id = hostname()
    if not available():
        return _render([], machine_id, probed=False)

    name = random_name()
    responders = probe(name=name)
    findings = assess(responders, name, machine_id)
    return _render(findings, machine_id, probed=True)


def register(registry) -> None:
    registry.register(
        "namewatch",
        skill_namewatch,
        aliases=[
            "llmnr", "mdns", "responder", "name resolution attack",
            "resolver check", "llmnr check",
            "naamvergiftiging",                             # NL
            "empoisonnement de noms",                       # FR
        ],
    )
