"""`timeline` skill — what changed on the LAN, and when (G7).

The read side of the guard's history. Each patrol pass records its
change-findings to a journal; this verb folds them into "here is what moved
on your network in the last week" — a new device, a moved IP, a device that
left, a newly-opened port, a live anomaly — each shown once with how long it
has been showing up.

    timeline           the last 7 days
    timeline 30        the last 30 days

Read-only: it summarises the journal, never scans. Honest empty-state: a
window with nothing recorded says so; a journal that was never written says
the patrol has not run yet — never "the LAN was quiet."
"""

import os
from typing import Any

from domains.timeline import summarize
from platform_support import hostname

_JOURNAL = os.path.join("data", "census", "guard_events.json")

_DEFAULT_DAYS = 7


def _days(args: str) -> int:
    for tok in (args or "").split():
        if tok.isdigit():
            return max(1, min(365, int(tok)))
    return _DEFAULT_DAYS


def _short(ts: str) -> str:
    # 2026-07-23T18:51:53+00:00 -> 2026-07-23 18:51
    return ts.replace("T", " ")[:16] if ts else ""


def _render(summary, machine_id: str) -> str:
    lines = [f"  NETWORK GUARD TIMELINE — {machine_id}", "  " + "=" * 58]

    if not summary.has_history:
        lines.append("  No guard history yet — the scheduled patrol writes it "
                     "as it runs.")
        lines.append("  (Run `patrol` once, or install the hourly timer: "
                     "packaging/systemd/install-timer.sh patrol.")
        lines.append("   Not an all-clear — nothing has been recorded.)")
        return "\n".join(lines)

    if not summary.changes:
        lines.append(f"  No changes recorded in the last {summary.since_days} "
                     f"day(s).")
        lines.append("  (The patrol ran and saw nothing move — steady, not a "
                     "guarantee nothing is wrong.)")
        lines += _truncation_notice(summary)
        return "\n".join(lines)

    lines.append(f"  {len(summary.changes)} change(s) on the LAN in the last "
                 f"{summary.since_days} day(s), newest first:")
    lines.append("")
    for c in summary.changes:
        mark = "!" if c.severity != "info" else "-"
        lines.append(f"   {mark} [{c.severity}] {c.message}")
        span = _short(c.last_ts)
        if c.count > 1:
            span = f"first {_short(c.first_ts)} · last {_short(c.last_ts)} · {c.count}×"
        else:
            span = f"at {_short(c.last_ts)}"
        lines.append(f"       {span}")
    lines += _truncation_notice(summary)
    return "\n".join(lines)


def _truncation_notice(summary) -> list:
    """Say when the window asked for is longer than the history kept.

    The journal trims to MAX_JOURNAL_LINES on every write, silently. Ask for
    30 days on a full journal reaching back 9 and the old answer was a
    confident "3 changes in the last 30 days" — about 21 days that had been
    dropped. Reporting a window you cannot see as if you had looked at it is
    the same lie as reporting an unchecked host as clean.
    """
    if not getattr(summary, "truncated", False):
        return []
    return [
        "",
        f"  ⚠ History older than {_short(summary.oldest_ts)} has been TRIMMED",
        "    (the journal is at capacity). This window is therefore",
        f"    incomplete — it is not {summary.since_days} days of evidence,",
        "    it is everything still on disk. Absence here is not absence of",
        "    events.",
    ]


def skill_timeline(args: str, speaker: Any = None) -> str:
    """Summarise what changed on the LAN over the last N days (default 7)."""
    del speaker
    machine_id = hostname()
    summary = summarize(_JOURNAL, since_days=_days(args))
    return _render(summary, machine_id)


def register(registry) -> None:
    registry.register(
        "timeline",
        skill_timeline,
        aliases=[
            "guard timeline", "lan history", "what changed", "changes",
            "network timeline", "what changed this week",
            "tijdlijn", "wat is er veranderd",              # NL
            "chronologie", "qu'est-ce qui a changé",        # FR
        ],
    )
