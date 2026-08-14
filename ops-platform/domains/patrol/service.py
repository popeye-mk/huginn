"""Patrol domain — decide when the guard should raise its voice (G4).

The always-on loop runs census + anomaly-watch + exposure on a schedule.
Most runs find nothing new; this layer decides which runs are worth an
alert, so the operator hears from the predecessor project only when something actually
changed — never a heartbeat email that trains them to ignore it.

An alert fires when a run produces any finding that is BOTH new and worth
attention:

- a **new device** on the LAN (census warning),
- a **live anomaly** — ARP spoof / rogue DHCP (guard warning),
- a **newly-opened dangerous port** (exposure, and only the *newly* ones,
  since a long-standing open port isn't news and known-good ones are
  already muted by the ack store).

Everything else — a device that left, an already-known exposure, a clean
run — is recorded but stays quiet. The decision is pure and testable here;
the fork owns the actual email send.
"""

from dataclasses import dataclass, field
from typing import List

from contracts.finding import sort_findings


@dataclass
class PatrolResult:
    """One patrol pass: everything seen, and the subset worth alerting on."""

    alert_findings: List = field(default_factory=list)   # new + noteworthy
    all_findings: List = field(default_factory=list)     # full record
    census_count: int = 0
    exposed_count: int = 0

    @property
    def should_alert(self) -> bool:
        return bool(self.alert_findings)


def _is_new_exposure(finding) -> bool:
    """An exposure finding only counts as news if it's NEWLY opened."""
    return "exposure" in (finding.tags or ()) and "NEWLY" in finding.message


def _is_alertworthy(finding) -> bool:
    """A finding worth waking the operator for."""
    if finding.severity == "info":
        return False
    tags = finding.tags or ()
    if "anomaly" in tags:
        return True                     # ARP spoof / rogue DHCP: always
    if "exposure" in tags:
        return _is_new_exposure(finding)  # only newly-opened ports
    if "lan" in tags and finding.severity in ("warning", "critical"):
        return True                     # new device (census warning)
    return False


def evaluate(census_findings, anomaly_findings, exposure_findings,
             census_count=0, exposed_count=0) -> PatrolResult:
    """Fold the three checks' findings into a patrol result.

    Takes the findings each verb produced this run (census already diffs
    against its own baseline, exposure already tags NEWLY, guard is
    inherently current-state), and selects the alert-worthy subset.
    """
    everything = list(census_findings or []) + list(anomaly_findings or []) \
        + list(exposure_findings or [])
    alerts = [f for f in everything if _is_alertworthy(f)]
    return PatrolResult(
        alert_findings=sort_findings(alerts),
        all_findings=sort_findings(everything),
        census_count=census_count,
        exposed_count=exposed_count,
    )


# A live anomaly that keeps coming back is not a blip — it is an attack that is
# still running. This is the threshold at which the guard says so.
_PERSIST_THRESHOLD = 3


def escalations(findings, counts, threshold=_PERSIST_THRESHOLD):
    """Anomaly findings the history shows recurring — persistent, not one-off.

    `counts` maps a finding id to how many times the timeline has recorded it
    (injected — this domain does not read the journal). For an anomaly finding
    seen at least `threshold` times, returns an escalation dict naming the
    count and what it means. Pure: same inputs, same escalations.
    """
    out = []
    for f in findings or []:
        if "anomaly" not in (f.tags or ()):
            continue                    # only live attacks escalate on repetition
        seen = int(counts.get(f.id, 0))
        if seen >= threshold:
            out.append({
                "id": f.id,
                "severity": f.severity,
                "message": f.message,
                "count": seen,
                "note": (f"Seen {seen}× — persistent, not a one-off. Treat it as "
                         f"an attack still in progress until you have found and "
                         f"removed the source."),
            })
    return out


def alert_event(result: PatrolResult, machine_id: str) -> dict:
    """Shape a patrol alert as the event dict the fork's emailer expects."""
    lines = []
    for f in result.alert_findings:
        lines.append(f"[{f.severity}] {f.message}")
        if f.suggested_action:
            lines.append(f"  -> {f.suggested_action}")
    return {
        "type": "network_guard_change",
        "machine": machine_id,
        "count": len(result.alert_findings),
        "summary": "; ".join(f.message for f in result.alert_findings),
        "detail": "\n".join(lines),
    }
