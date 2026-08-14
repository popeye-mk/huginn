"""Name-poisoning domain (G8) — turn decoy-probe replies into a finding.

The engine sends a query for a name that cannot exist and returns whoever
answered. The meaning is stark and needs no threshold: on an honest LAN the
list is empty, so **any** responder is a host answering for names it does
not own — a Responder-style poisoner. One finding, `critical`, naming the
IP(s) and the fix.

Absence discipline: an empty result from a probe that *could not run* is
not a clean bill of health. The engine reports whether it could probe; this
domain only turns real replies into findings, and the verb prints the
"not checked" case honestly.
"""

from typing import List

from contracts.finding import Coverage, Finding


def assess(responders, probed_name: str, machine_id: str) -> List[Finding]:
    """Any reply to the decoy name is poisoning. Returns 0 or 1 finding."""
    if not responders:
        return []

    ips = sorted({r.ip for r in responders})
    protos = sorted({r.proto for r in responders})
    where = ", ".join(ips)
    how = "/".join(protos)
    return [Finding(
        id=f"lan_name_poison_{ips[0]}",
        source_module="lan-poison",
        machine_id=machine_id,
        severity="critical",
        confidence="likely",
        message=(f"Name-resolution poisoning: {where} answered a query for a "
                 f"non-existent name over {how}."),
        coverage=Coverage(checked=len(responders), total=len(responders)),
        suggested_action=(
            "A host answering for names that do not exist is a Responder-style "
            "attacker harvesting credentials. Isolate that IP, then disable "
            "LLMNR and NBT-NS on your machines via GPO (the standing "
            "hardening) so this cannot work again."),
        plain_message=(
            "Something on your network is lying about who owns a name — the "
            "classic trick for stealing Windows logins. Find that device and "
            "take it off the network."),
        tags=("anomaly", "lan", "security"),
    )]
