"""`capture` skill — freeze the evidence now (H2).

When the guard raises something at 03:00 and you look at 08:00, the ARP cache
has aged, the lease has renewed and the interesting connection has closed.
This captures the volatile state at one moment into a timestamped file, and
prints a short summary.

    capture

Fast and safe by construction: it only READS state this host already holds —
neighbour table, gateway, DHCP server, subnets, own listening ports, posture
flags and the guard's recent timeline. No scan, no probe, no network traffic,
so it is honest to run while an attack is live. Anything unreadable is listed
as unreadable, never as empty.

The collection itself lives in `agents/capturing.py` because `patrol` triggers
it automatically on an alert — and a platform skill must never import another
skill (the fork's `skills` package shadows ours; that was a live outage).
"""

from typing import Any

from agents.capturing import take_snapshot
from domains.incident import render_summary
from platform_support import hostname


def skill_capture(args: str, speaker: Any = None) -> str:
    """Freeze the volatile evidence into a timestamped incident file."""
    del args, speaker
    snapshot, path = take_snapshot(hostname(), reason="manual")
    if not path:
        return (render_summary(snapshot)
                + "\n\n  Could NOT be written — the summary above is all that "
                  "survives this run.")
    return render_summary(snapshot, path)


def register(registry) -> None:
    registry.register(
        "capture",
        skill_capture,
        aliases=[
            "incident", "snapshot", "freeze", "evidence", "forensics",
            "momentopname",                                 # NL
            "instantané",                                   # FR
        ],
    )
