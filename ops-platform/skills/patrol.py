"""`patrol` skill — one unattended guard pass (G4).

Runs the three Network-Guard checks back to back — census (who's here),
guard (ARP spoof / rogue DHCP), expose (open ports) — and returns both a
human summary and a machine-readable signal of whether anything changed.

When `should_alert` is true the findings go to `agents.alerting`, which
hands them to whichever channels the registered administrator has enabled
in `data/admin.json` — desktop toast, ntfy push, email — and reports, per
channel, whether the alert actually arrived.

**This paragraph used to describe something else, and the difference is
the reason the module exists.** Until 2026-07-27 it read: "The fork bridge
calls this, and when `should_alert` is true hands the `alert_event` to the
operator's already-configured `send_security_alert`." That function lived
in the vendored fork, which was archived on 2026-07-26. Nothing replaced
it. For a day `should_alert` computed correctly, the evidence was frozen,
the timeline was written — and no human was ever told, with nothing
raising and nothing logged, because delivery had no code left to fail in.
Alerting now returns a `Delivery` per channel for exactly that reason: a
path that cannot report its own absence will eventually take one.
"""

import os
from datetime import datetime, timezone
from typing import Any

from agents.alerting import raise_alert, render_delivery
from agents.capturing import take_snapshot
from agents.patrolling import run_patrol
from agents.surveying import record_pass
from agents.witnessing import read_observations, record
from engines.wifi_scan import read_radios
from domains.corroboration import assess as cross_assess
from domains.wifi import assess as wifi_assess, load_baseline
from domains.patrol import alert_event, escalations
from domains.timeline import append_events, summarize
from platform_support import hostname

# The guard timeline (G7) is fed here: each patrol pass records its
# change-findings so `timeline` can answer "what changed this week." Only the
# patrol path records — `mitigate` reuses run_patrol for advice and must not
# write history. Failure to record never breaks a patrol.
_TIMELINE_JOURNAL = os.path.join("data", "census", "guard_events.json")


def _record_timeline(result, machine_id) -> None:
    if result is None:
        return
    try:
        append_events(_TIMELINE_JOURNAL, result.all_findings, machine_id)
    except Exception:  # noqa: BLE001 - history is best-effort, never fatal
        pass


def _capture_on_alert(result, machine_id):
    """Freeze the evidence the moment the guard decides something is wrong.

    The reason this is automatic: volatile state ages in minutes. A patrol that
    alerts at 03:00 and an operator who reads it at 08:00 are looking at
    different networks — the ARP cache has turned over, the lease has renewed,
    the connection has closed. Capturing at detection time means the evidence
    that justified the alert still exists when someone comes to check it.

    Only on a real alert (never on a quiet pass, or there would be a snapshot
    every 3 hours forever), and never fatal: a capture that fails costs the
    operator nothing they had before.
    """
    if result is None or not result.should_alert:
        return ""
    try:
        reason = "; ".join(f.message for f in result.alert_findings[:3]) or "alert"
        _, path = take_snapshot(machine_id, reason=f"patrol alert: {reason}")
        return path
    except Exception:  # noqa: BLE001 - evidence is a bonus, never a blocker
        return ""


def _persistent(result):
    """Escalations for anomalies the history shows recurring (G11).

    Reads the guard timeline (over a month) for how many times each finding has
    been recorded, and asks the patrol domain which are persistent. Best-effort:
    no journal or a read error just means no escalation this pass.
    """
    try:
        summary = summarize(_TIMELINE_JOURNAL, since_days=30)
        counts = {c.id: c.count for c in summary.changes}
    except Exception:  # noqa: BLE001
        return []
    return escalations(result.alert_findings, counts)


def _render(result, machine_id, persistent=None, capture_path="") -> str:
    lines = ["  NETWORK GUARD PATROL — " + machine_id, "  " + "=" * 58]
    lines.append(f"  {result.census_count} device(s) seen; "
                 f"{result.exposed_count} with an open port.")
    if not result.should_alert:
        lines.append("  No changes worth alerting on this pass.")
        lines.append("  (A quiet patrol is not a guarantee of safety — only "
                     "that nothing new was seen in what was checked.)")
        return "\n".join(lines)
    if persistent:
        lines += ["", "  ‼ PERSISTENT — these are still happening:"]
        for e in persistent:
            lines.append(f"   ‼ [{e['severity']}] {e['message']}  ({e['count']}×)")
            lines.append(f"       -> {e['note']}")
    lines += ["", f"  {len(result.alert_findings)} change(s) worth your attention:"]
    for f in result.alert_findings:
        lines.append(f"   ! [{f.severity}] {f.message}")
        if f.suggested_action:
            lines.append(f"       -> {f.suggested_action}")
    if capture_path:
        lines += ["", f"  Evidence frozen at detection time: {capture_path}",
                  "  (Captured now, because the neighbour table and leases this "
                  "alert rests on will have changed by morning.)"]
    return "\n".join(lines)


def skill_patrol(args: str, speaker: Any = None) -> str:
    """Run one guard patrol: census + anomaly + exposure, alert on change."""
    del args, speaker
    machine_id = hostname()
    result = run_patrol(machine_id)
    if result is None:
        return ("Patrol could not read the LAN (the neighbour/ARP tool did "
                "not answer). Not an all-clear — nothing could be checked.")
    _record_timeline(result, machine_id)      # record first so the count is current
    # Mark that a pass HAPPENED, not only that it found something. The
    # journal above records changes, so a quiet patrol leaves it untouched —
    # and a stopped timer leaves it untouched in exactly the same way. This
    # is the one line that tells those two apart.
    record_pass(machine_id, result)
    cross = _corroborate(machine_id) + _radio_watch(machine_id)
    text = _render(result, machine_id, persistent=_persistent(result),
                   capture_path=_capture_on_alert(result, machine_id))
    if cross:
        text += "\n\n  CROSS-CHECK (other witnesses, and the air):"
        for finding in cross:
            text += f"\n   ! [{finding.severity}] {finding.message}"
    return text + _deliver_alert(result, machine_id, extra=cross)


def _corroborate(machine_id):
    """Publish this host's view, then check it against the other witnesses.

    Runs on every patrol so the second machine's file is never stale by
    neglect, and so a gateway-MAC conflict ALERTS rather than waiting for
    someone to type `corroborate`. A disagreement about the gateway is the
    strongest single-signal evidence of ARP spoofing this tool can produce;
    leaving it behind a manual verb would mean it is found only by an
    operator who already suspected something.

    Best-effort throughout: no observations, no peers, or an unwritable
    directory all mean "no corroboration this pass", never a failed patrol.
    Only findings above `info` are returned — partial visibility between two
    hosts is normal on a switched network and would be hourly noise.
    """
    try:
        record(machine_id)
        now = datetime.now(timezone.utc)
        found = cross_assess(read_observations(), machine_id, now)
        return [f for f in found if f.severity != "info"]
    except Exception:                       # noqa: BLE001
        return []


def _radio_watch(machine_id):
    """Check the air for a radio impersonating a confirmed network.

    On the hourly patrol rather than only in the `wifi` verb, for the reason
    this whole chapter opened with: a detector that runs when the operator
    is already looking adds very little to someone who was already looking.
    An evil twin appears while you are working, not while you are auditing.

    Only findings above `info` are returned, and the baseline is required —
    with nothing confirmed there is nothing that can be called unexpected,
    and `assess` correctly returns nothing. Best-effort throughout: a
    machine with no Wi-Fi produces no findings and no error.
    """
    try:
        baseline = load_baseline()
        if not baseline:
            return []                       # see the `wifi` verb; not a pass
        found = wifi_assess(read_radios(), baseline, machine_id)
        return [f for f in found if f.severity != "info"]
    except Exception:                       # noqa: BLE001
        return []


def _deliver_alert(result, machine_id, extra=None) -> str:
    """Tell the registered administrator, and say whether that worked.

    Appends to the patrol summary rather than replacing anything: the text
    is what the operator reads at the console, and "who was told" belongs
    beside "what was found". Best-effort by construction — a notifier that
    threw would otherwise turn a successful detection into a failed verb,
    which is the wrong trade in both directions.
    """
    extra = list(extra or [])
    # A corroboration conflict is worth waking someone for even on a pass
    # the guard itself called quiet: the local cache can look perfectly
    # consistent while being the one that was rewritten. It is precisely the
    # attack a single host cannot see, so it must not depend on that host
    # having also noticed something.
    if result is None or (not result.should_alert and not extra):
        return ""
    findings = list(result.alert_findings if result is not None else []) + extra
    try:
        alert, deliveries = raise_alert(findings, machine_id)
        rendered = render_delivery(alert, deliveries)
        return ("\n\n" + rendered) if rendered else ""
    except Exception as exc:                  # noqa: BLE001
        return ("\n\n  ALERT NOT DELIVERED — the alerting path itself failed "
                f"({type(exc).__name__}). The findings above are recorded; "
                "nobody has been notified.")


# Kept for callers that want the structured event as well as the text.
# The fork bridge it was written for is gone (archived 2026-07-26);
# delivery now happens inside skill_patrol via agents.alerting.
def patrol_alert(machine_id=None):
    """Run a patrol and return (summary_text, alert_event_or_None)."""
    machine_id = machine_id or hostname()
    result = run_patrol(machine_id)
    if result is None:
        return ("Patrol could not read the LAN.", None)
    _record_timeline(result, machine_id)
    record_pass(machine_id, result)
    persistent = _persistent(result)
    capture_path = _capture_on_alert(result, machine_id)
    text = _render(result, machine_id, persistent=persistent,
                   capture_path=capture_path)
    event = alert_event(result, machine_id) if result.should_alert else None
    if event is not None and capture_path:
        event["evidence"] = capture_path
        event["detail"] += f"\n\nEvidence frozen at detection: {capture_path}"
    if event is not None and persistent:
        # A persistent attack is the reason to read this email first.
        event["persistent"] = len(persistent)
        event["detail"] = ("PERSISTENT (still happening):\n"
                           + "\n".join(f"  {e['message']} ({e['count']}×)"
                                       for e in persistent)
                           + "\n\n" + event["detail"])
    return (text, event)


def register(registry) -> None:
    registry.register(
        "patrol",
        skill_patrol,
        aliases=[
            "guard patrol", "network patrol", "sweep and watch",
            "netwerkpatrouille",                          # NL
            "patrouille réseau",                          # FR
        ],
    )
