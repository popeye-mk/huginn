"""Weekly guard digest (G12) — one briefing from the state already kept.

The dashboard is a live pane of glass; the digest is the thing you *read* — a
short weekly summary folding the device count, what changed this week (G7),
and any persistent attack (G11) into a few lines fit for an email or a Monday
glance. It computes nothing: the caller injects the summaries it already has,
this only arranges them. Pure — same inputs, same briefing.

Honesty carries over: no timeline history says "the patrol has not run," not
"the LAN was quiet"; a device count is what was *last seen*, never a promise
the LAN is safe.
"""


def _changes_section(changes):
    lines = []
    for c in changes:
        span = f"{c['count']}×, last {c.get('last', '')[:16]}" if c.get("count", 1) > 1 \
            else c.get("last", "")[:16]
        lines.append(f"   - [{c['severity']}] {c['message']}  ({span})")
    return lines


def build_digest(machine_id, devices, exposed, critical, changes,
                 persistent, has_history, since_days=7, truncated=False,
                 oldest_ts=""):
    """Arrange the injected guard summaries into a weekly briefing string."""
    lines = [f"  NETWORK GUARD — WEEKLY DIGEST ({machine_id})", "  " + "=" * 58]
    lines.append(f"  {devices} device(s) last seen · {exposed} with an open "
                 f"port · {critical} critical.")

    if persistent:
        lines += ["", "  ‼ PERSISTENT — still happening:"]
        for e in persistent:
            lines.append(f"   ‼ [{e['severity']}] {e['message']}  ({e['count']}×)")

    lines += ["", f"  What changed in the last {since_days} day(s):"]
    if truncated:
        # The window is bounded by what survived the journal trim,
        # not by the days requested. Say so rather than implying the
        # briefing covers a period it cannot see.
        lines.append(f"  (History before {oldest_ts[:16]} has been trimmed —"
                     " this covers less than the days above.)")
    if not has_history:
        lines.append("   (No guard history yet — the scheduled patrol writes "
                     "it. Not an all-clear.)")
    elif not changes:
        lines.append("   Nothing moved. (Steady, not a guarantee of safety.)")
    else:
        lines += _changes_section(changes)

    lines += ["", "  Read-only summary. Run `patrol`, `expose` or `dashboard` "
              "for detail."]
    return "\n".join(lines)
