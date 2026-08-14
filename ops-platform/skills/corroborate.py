"""`corroborate` skill — compare what every witnessing host saw.

    corroborate          compare all observations, report agreement or conflict
    corroborate record   write THIS host's observation and stop

Every guard finding in this platform rests on one machine's ARP cache — and
one cache is exactly what an ARP-spoofing attacker rewrites. The tool has
always said so honestly. Honesty about a blind spot does not remove it.

A second host holding its own cache can *disagree*, and the disagreement is
worth more than either reading alone. That is the whole verb: not another
detector, a second witness.

Three things it refuses to do:

- **Report agreement as safety.** Two hosts can agree and both be lied to;
  one attacker poisoning both caches produces perfect consensus.
- **Report one witness as corroboration.** A lone observation corroborates
  nothing and says so.
- **Count a stale witness.** A machine that has been off since yesterday
  describes yesterday's network. Past the freshness window it stops being
  evidence — reported, never silently dropped.
"""

import os
from datetime import datetime, timezone
from typing import Any

from agents.witnessing import observation_dir, read_observations, record
from domains.corroboration import DEFAULT_MAX_AGE_MINUTES, assess, verdict
from platform_support import hostname


def _render_split(state: dict) -> list:
    """Why two witnesses that exist still cannot corroborate.

    Saying only "cannot corroborate" beside two host names reads as a fault.
    It is topology — different gateways are different broadcast domains — and
    the operator needs to know which, plus what would change it.
    """
    lines = [f"  {state['host_count']} hosts witnessing, but on DIFFERENT networks:"]
    for gateway, who in (state.get("segments") or {}).items():
        lines.append(f"    via {gateway:<16} {', '.join(who)}")
    return lines + [
        "",
        "  They cannot corroborate each other. Different gateways means",
        "  different broadcast domains — neither can see what the other sees,",
        "  and comparing their gateway MACs would compare two unrelated",
        "  routers.",
        "",
        "  To make them witnesses, put them on the SAME segment: bridge the",
        "  VM to the physical LAN instead of NAT, or run the second witness",
        "  on a machine that is already there.",
    ]


def _render_verdict(state: dict, observations) -> list:
    lines = []
    if not observations:
        lines += [
            "  No observations found at all.",
            f"  (Looked in {observation_dir()}/)",
            "",
            "  Run `corroborate record` here, and on the second machine, then",
            "  point both at the same folder. Until then this host is the only",
            "  witness to its own network.",
        ]
        return lines

    if state["host_count"] == 0:
        lines.append("  Observations exist, but none is recent enough to count.")
    elif state["host_count"] == 1:
        lines += [
            f"  Only ONE host is currently witnessing: {state['hosts'][0]}.",
            "  Nothing can be corroborated — this is a single ARP cache, which",
            "  is exactly what an ARP-spoofing attacker rewrites.",
        ]
    elif state.get("split_across_segments") and not state["can_corroborate"]:
        lines += _render_split(state)
    else:
        lines.append(f"  {state['host_count']} hosts witnessing: "
                     f"{', '.join(state['hosts'])}.")

    if state["stale"]:
        lines.append(f"  STALE (older than {state['max_age_minutes']} min, not "
                     f"counted): {', '.join(state['stale'])}")
        lines.append("   → a machine that has been off describes the network it "
                     "last saw, not this one.")
    if state.get("blind"):
        lines.append(f"  SAW NOTHING (present, not counted): "
                     f"{', '.join(state['blind'])}")
        lines.append("   → reported successfully and observed no gateway and no "
                     "neighbours.")
        lines.append("     A host with its interface down, or on an isolated "
                     "network, writes a")
        lines.append("     perfectly valid file describing nothing. Counting it "
                     "would turn")
        lines.append("     \"nobody else can see this\" into \"another host "
                     "disagrees\".")
    if state["unreadable"]:
        lines.append(f"  COULD NOT READ their neighbours: "
                     f"{', '.join(state['unreadable'])}")
        lines.append("   → present, but blind. Not a witness to anything.")
    return lines


def _render(observations, findings, state: dict) -> str:
    lines = ["  LAN CORROBORATION", "  " + "=" * 58]
    lines += _render_verdict(state, observations)

    if findings:
        lines += ["", f"  {len(findings)} finding(s):"]
        for f in findings:
            mark = "!" if f.severity != "info" else "-"
            lines.append(f"   {mark} [{f.severity}] {f.message}")
            if f.suggested_action:
                lines.append(f"       -> {f.suggested_action}")
    elif state["can_corroborate"]:
        lines += ["", "  The witnesses agree on the gateway."]

    if state["can_corroborate"]:
        lines += [
            "",
            "  Agreement is not proof. Two hosts can agree and both be wrong —",
            "  one attacker poisoning both caches produces perfect consensus.",
            "  This raises confidence; it does not establish truth.",
        ]
    return "\n".join(lines)


def skill_corroborate(args: str, speaker: Any = None) -> str:
    """Compare observations from every witnessing host."""
    del speaker
    machine_id = hostname()

    if (args or "").strip().lower().startswith("record"):
        path = record(machine_id)
        if not path:
            return ("Could not write this host's observation (the directory is "
                    "not writable). Nothing was recorded — not an all-clear.")
        return (f"  Observation written: {path}\n"
                "  Copy or sync this folder to the other machine, and run\n"
                "  `corroborate` on either one.")

    # Always refresh our own first: comparing a stale self against a fresh
    # peer would report a disagreement that is really just a clock.
    #
    # The RESULT is checked, and that is not fussiness. The first live run
    # against a shared folder wrote nothing — the mount had not happened and
    # the path was a root-owned local directory, so the write failed with
    # permission denied. `record` swallowed it, this line discarded the empty
    # return, and the verb reported "nothing has been written yet": a benign
    # empty state, when the truth was "I tried to write and could not". The
    # operator would have gone looking at the OTHER machine for a file this
    # one had never managed to produce.
    written = record(machine_id)

    observations = read_observations()
    now = datetime.now(timezone.utc)
    state = verdict(observations, now, DEFAULT_MAX_AGE_MINUTES)
    findings = assess(observations, machine_id, now, DEFAULT_MAX_AGE_MINUTES)
    text = _render(observations, findings, state)

    if not written:
        text = ("  ⚠ THIS HOST COULD NOT WRITE ITS OWN OBSERVATION\n"
                f"    to {observation_dir()}\n"
                "    Usually: the shared folder is not mounted, or is not\n"
                "    writable by this user. Whatever is reported below is\n"
                "    missing THIS machine — and is not an all-clear.\n\n") + text
    return text


def register(registry) -> None:
    registry.register(
        "corroborate",
        skill_corroborate,
        aliases=[
            "second opinion", "cross check", "compare hosts", "witnesses",
            "bevestigen", "tweede mening",                  # NL
            "corroborer", "deuxième avis",                  # FR
        ],
    )
