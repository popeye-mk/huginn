"""`digest` skill — the weekly guard briefing (G12).

Folds the state the guard already keeps into one short summary you can read on
a Monday (or wire to a weekly email like `patrol` does): how many devices, how
exposed, what changed in the last week, and any attack that keeps coming back.

    digest            the last 7 days
    digest 30         the last 30 days

Read-only: it summarises the census/exposure baselines and the G7 timeline,
scans nothing, sends nothing. Honest empty-states are inherited from the pieces
it folds — no history says the patrol has not run, not that the LAN is clean.
"""

import os
from typing import Any

from domains.census import load_baseline
from domains.dashboard import build_state
from domains.digest import build_digest
from domains.exposure import load_exposure_baseline
from domains.timeline import summarize
from platform_support import hostname

_CENSUS_BASELINE = os.path.join("data", "census", "lan_baseline.json")
_EXPO_BASELINE = os.path.join("data", "census", "exposure_baseline.json")
_TIMELINE_JOURNAL = os.path.join("data", "census", "guard_events.json")

# A recurring change is a persistent *attack* only if it is a name-resolution /
# ARP / DHCP anomaly — matched on the stable message wording, so the digest
# needs no tag in the journal.
_ATTACK_WORDS = ("spoof", "poison", "rogue dhcp", "mitm", "impersonat")
_PERSIST_THRESHOLD = 3


def _days(args: str) -> int:
    for tok in (args or "").split():
        if tok.isdigit():
            return max(1, min(365, int(tok)))
    return 7


def skill_digest(args: str, speaker: Any = None) -> str:
    """Assemble the weekly guard digest from the kept state."""
    del speaker
    machine_id = hostname()
    days = _days(args)

    state = build_state(load_baseline(_CENSUS_BASELINE),
                        load_exposure_baseline(_EXPO_BASELINE))
    summary = summarize(_TIMELINE_JOURNAL, since_days=days)
    changes = [{"severity": c.severity, "message": c.message,
                "count": c.count, "last": c.last_ts} for c in summary.changes]
    persistent = [
        ch for ch in changes
        if ch["count"] >= _PERSIST_THRESHOLD
        and any(w in ch["message"].lower() for w in _ATTACK_WORDS)
    ]
    return build_digest(
        machine_id, state.device_count, state.exposed_count,
        state.critical_count, changes, persistent, summary.has_history,
        since_days=days, truncated=summary.truncated,
        oldest_ts=summary.oldest_ts,
    )


def register(registry) -> None:
    registry.register(
        "digest",
        skill_digest,
        aliases=[
            "weekly digest", "guard digest", "weekly summary", "briefing",
            "weekoverzicht",                                # NL
            "résumé hebdomadaire",                          # FR
        ],
    )
