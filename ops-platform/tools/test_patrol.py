"""Tests for the patrol domain (G4) — decide when to alert.

The point of the loop is to email only on a real change. These pin exactly
that: a new device / live anomaly / newly-opened port fires an alert, while
a device that left, an already-open port, or a clean run stays quiet — no
heartbeat spam.

Run: python3 tools/test_patrol.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.finding import Coverage, Finding  # noqa: E402
from domains.patrol import alert_event, escalations, evaluate  # noqa: E402


def _f(fid, severity, message, tags, action="do x"):
    return Finding(
        id=fid, source_module="lan-census", machine_id="host",
        severity=severity, confidence="certain", message=message,
        coverage=Coverage(checked=1, total=1), suggested_action=action,
        tags=tags,
    )


def test_new_device_fires_an_alert():
    census = [_f("lan_new_device_x", "warning", "New device on the LAN: x",
                 ("security", "lan"))]
    r = evaluate(census, [], [])
    assert r.should_alert
    assert len(r.alert_findings) == 1


def test_live_anomaly_fires_an_alert():
    anomaly = [_f("arp_dup_ip_1", "warning", "One IP claimed by several MACs",
                  ("security", "lan", "anomaly"))]
    r = evaluate([], anomaly, [])
    assert r.should_alert


def test_newly_opened_port_fires_but_old_one_does_not():
    new = _f("exposure_1_23", "critical",
             "1 exposes Telnet (port 23) (NEWLY opened since last scan)",
             ("security", "lan", "exposure"))
    old = _f("exposure_1_445", "critical", "1 exposes SMB (port 445)",
             ("security", "lan", "exposure"))
    r = evaluate([], [], [new, old])
    ids = [f.id for f in r.alert_findings]
    assert "exposure_1_23" in ids          # newly opened -> alert
    assert "exposure_1_445" not in ids     # long-standing -> quiet


def test_vanished_device_stays_quiet():
    census = [_f("lan_gone_x", "info", "Device no longer seen: x",
                 ("security", "lan"))]
    r = evaluate(census, [], [])
    assert not r.should_alert               # info -> never an alert


def test_clean_run_is_quiet():
    r = evaluate([], [], [], census_count=12, exposed_count=1)
    assert not r.should_alert
    assert r.census_count == 12


def test_alert_event_has_summary_and_detail():
    census = [_f("lan_new_device_x", "warning", "New device on the LAN: x",
                 ("security", "lan"))]
    r = evaluate(census, [], [])
    ev = alert_event(r, "host")
    assert ev["type"] == "network_guard_change"
    assert ev["count"] == 1
    assert "New device" in ev["summary"]
    assert "-> " in ev["detail"]            # the fix line is included


# --- G11: escalate a persistent anomaly -----------------------------------

def test_a_recurring_anomaly_escalates():
    anomaly = _f("arp_dup_ip_1", "warning", "One IP claimed by several MACs",
                 ("security", "lan", "anomaly"))
    esc = escalations([anomaly], counts={"arp_dup_ip_1": 4})
    assert len(esc) == 1 and esc[0]["count"] == 4, "seen 4x (>= 3) → escalated"
    assert "persistent" in esc[0]["note"].lower(), "the note explains what it means"


def test_a_one_off_anomaly_does_not_escalate():
    anomaly = _f("arp_dup_ip_1", "warning", "One IP claimed by several MACs",
                 ("security", "lan", "anomaly"))
    assert escalations([anomaly], counts={"arp_dup_ip_1": 2}) == [], "seen 2x (< 3) → no escalation"
    assert escalations([anomaly], counts={}) == [], "never-before-seen → no escalation"


def test_a_non_anomaly_never_escalates():
    # A new device or an open port, however often it recurs, is not an attack
    # in progress — only anomalies escalate on repetition.
    device = _f("lan_new_device_x", "warning", "New device on the LAN: x", ("security", "lan"))
    assert escalations([device], counts={"lan_new_device_x": 9}) == [], "only anomalies escalate"


# --- H2b: the guard freezes evidence at detection time --------------------

def test_an_alerting_patrol_captures_but_a_quiet_one_does_not():
    """Volatile state ages in minutes, so evidence is frozen when the guard
    decides — not when the operator reads the email. But only on a real alert:
    capturing every quiet pass would mean a snapshot every 3 hours forever.

    `take_snapshot` is STUBBED here on purpose. The first version of this test
    called the real one, which reads the live host — on Windows that is up to
    six PowerShell invocations plus netstat/arp/netsh, and it failed on the
    b023 disc (30/31) while passing on Linux, where those tools are absent and
    fail fast. The engines are injectable precisely so tests do not touch the
    machine; the decision under test here is *whether* to capture, not what a
    capture reads. The reading itself is covered by test_posture's snapshot
    round-trip, which uses no host I/O either.
    """
    from domains.patrol import PatrolResult
    import skills.patrol as patrol

    calls = []
    original = patrol.take_snapshot
    patrol.take_snapshot = lambda machine_id=None, reason="", **k: (
        calls.append(reason) or ({}, "data/census/incidents/incident-TEST.json"))
    try:
        anomaly = _f("arp_dup_ip_1", "warning", "One IP claimed by several MACs",
                     ("security", "lan", "anomaly"))
        alerting = PatrolResult(alert_findings=[anomaly], all_findings=[anomaly])
        path = patrol._capture_on_alert(alerting, "host")
        assert path, "an alerting patrol freezes the evidence"
        assert calls and "One IP claimed" in calls[0], \
            "the triggering finding is recorded as the capture reason"

        quiet = PatrolResult(alert_findings=[], all_findings=[])
        assert patrol._capture_on_alert(quiet, "host") == "", "a quiet pass captures nothing"
        assert len(calls) == 1, "and it did not even try — exactly one capture"

        rendered = patrol._render(alerting, "host", capture_path=path)
        assert "Evidence frozen at detection time" in rendered, "and the operator is told"
    finally:
        patrol.take_snapshot = original


def test_a_capture_failure_never_costs_the_patrol():
    """Evidence is a bonus; a patrol that alerts must still alert."""
    from domains.patrol import PatrolResult
    import skills.patrol as patrol
    original = patrol.take_snapshot
    patrol.take_snapshot = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
    try:
        anomaly = _f("arp_dup_ip_1", "warning", "spoof", ("security", "lan", "anomaly"))
        result = PatrolResult(alert_findings=[anomaly], all_findings=[anomaly])
        assert patrol._capture_on_alert(result, "host") == "", "failure is swallowed"
        assert "worth your attention" in patrol._render(result, "host"), "the alert survives"
    finally:
        patrol.take_snapshot = original


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
