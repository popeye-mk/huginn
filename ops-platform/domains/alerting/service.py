"""Alerting domain — turning findings into something worth waking someone for.

Pure. No sockets, no subprocess, no clock it did not receive. Everything
here is a decision, and the decisions are the point:

**What earns an alert.** Not everything the guard records. `info` is
routine churn — a phone leaving the network is a real change and correctly
journalled, and equally correctly not worth a notification. The scheduled
wrapper learned this the hard way in item 1: eleven `lan_gone_*` lines
reported as an incident. Same rule, same reason, one layer up.

**What quiet hours may and may not hold.** Quiet hours exist so routine
warnings do not wake anyone at 04:00. They are NEVER allowed to hold a
critical alert. An ARP-spoofing gateway at 04:00 is the exact moment the
operator most needs to know, and a "do not disturb" that silenced it would
be this project's founding failure wearing a friendly face.
"""

from datetime import datetime
from typing import Iterable, List, Optional

from contracts.alert import SEVERITY_ORDER, Alert

#: Below this, nothing is delivered. Findings quieter than this still reach
#: the journal and the timeline — they are recorded, just not announced.
DEFAULT_MIN_SEVERITY = "warning"

#: How many findings get spelled out in the message body. The rest are
#: counted, never dropped silently.
MAX_DETAIL = 5


def _rank(severity: str) -> int:
    """Position in SEVERITY_ORDER; anything unknown ranks above all of it.

    Deliberately not `.get(sev, 0)`. A severity this code has not been
    taught about must be treated as MORE urgent than the ones it knows,
    so a new level added upstream starts by being noticed rather than
    silently falling below the delivery threshold.
    """
    key = (severity or "").strip().lower()
    try:
        return SEVERITY_ORDER.index(key)
    except ValueError:
        return len(SEVERITY_ORDER)


def normalise_threshold(min_severity: str) -> str:
    """The configured bar, or the default if it is not a severity we know.

    **The asymmetry here is deliberate, and it is the point.** An unknown
    severity on a *finding* ranks above everything (surface it). An unknown
    *threshold* falls back to the default — because ranking it above
    everything would mean nothing ever clears it, and a typo in
    `data/admin.json` would silently switch off every alert. One typo, no
    error, no delivery, and a console that looks exactly like a quiet
    network. Both rules bend the same way: toward noise, never toward
    silence.
    """
    key = (min_severity or "").strip().lower()
    return key if key in SEVERITY_ORDER else DEFAULT_MIN_SEVERITY


def worth_alerting(findings, min_severity: str = DEFAULT_MIN_SEVERITY) -> List:
    """The findings that clear the announcement bar, most urgent first."""
    threshold = _rank(normalise_threshold(min_severity))
    kept = [f for f in (findings or [])
            if _rank(getattr(f, "severity", "")) >= threshold]
    kept.sort(key=lambda f: _rank(getattr(f, "severity", "")), reverse=True)
    return kept


def peak_severity(findings) -> str:
    """The most urgent severity present. Empty input is 'info', not a crash."""
    best, best_rank = "info", -1
    for finding in findings or []:
        severity = (getattr(finding, "severity", "") or "").strip().lower()
        rank = _rank(severity)
        if rank > best_rank:
            best, best_rank = severity or "info", rank
    return best


def in_quiet_hours(now: datetime, start: Optional[int], end: Optional[int]) -> bool:
    """Whether `now` falls in the configured quiet window (local hours).

    Handles a window that wraps midnight (22 -> 7), which is the shape
    almost everyone actually wants and the one an unguarded `start <= h <
    end` gets wrong.
    """
    if start is None or end is None:
        return False
    hour = now.hour
    if start == end:
        return False                      # a zero-width window mutes nothing
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end    # wraps midnight


def should_deliver(alert: Alert, now: datetime,
                   quiet_start: Optional[int] = None,
                   quiet_end: Optional[int] = None) -> bool:
    """Whether to announce this alert now.

    Critical ALWAYS delivers. Quiet hours are a courtesy for warnings, not
    a mute switch for emergencies — see the module docstring.
    """
    if alert.is_critical:
        return True
    return not in_quiet_hours(now, quiet_start, quiet_end)


def build_alert(findings, machine: str, now: datetime,
                min_severity: str = DEFAULT_MIN_SEVERITY,
                max_detail: int = MAX_DETAIL) -> Optional[Alert]:
    """Compose one alert from a patrol's findings, or None if none qualify.

    None means "nothing to announce" — it does NOT mean nothing happened.
    The findings are already in the journal either way; this decides only
    whether a human gets interrupted.
    """
    kept = worth_alerting(findings, min_severity)
    if not kept:
        return None

    severity = peak_severity(kept)
    shown = kept[:max_detail]
    hidden = len(kept) - len(shown)

    if len(kept) == 1:
        title = f"{severity}: {_message_of(kept[0])}"
    else:
        title = f"{len(kept)} findings on {machine} — worst is {severity}"

    lines = [f"Huginn — {machine} — {now.strftime('%Y-%m-%d %H:%M')}", ""]
    for finding in shown:
        lines.append(f"[{_severity_of(finding)}] {_message_of(finding)}")
    if hidden > 0:
        lines.append(f"… and {hidden} more (not shown, not dropped)")
    lines += [
        "",
        "This is what was measured, not a diagnosis. Huginn proposes; she",
        "does not act on the network.",
        "",
        "See it all:  huginn timeline     Freeze evidence:  huginn capture",
    ]

    return Alert(
        machine=machine,
        severity=severity,
        title=title[:200],
        body="\n".join(lines),
        raised_at=now.isoformat(timespec="seconds"),
        finding_ids=[getattr(f, "id", "") for f in kept],
        finding_count=len(kept),
    )


def _severity_of(finding) -> str:
    return (getattr(finding, "severity", "") or "info").strip().lower()


def _message_of(finding) -> str:
    return (getattr(finding, "message", "") or "").strip() or "(no message)"
