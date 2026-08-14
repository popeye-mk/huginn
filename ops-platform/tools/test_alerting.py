"""Tests for alert delivery — the path that went missing for a day.

Chapter two exists because `send_security_alert` was archived with the fork
on 2026-07-26, nothing replaced it, and `should_alert` went on computing
correctly while no human was ever told. Nothing raised. Nothing logged. The
failure was invisible because delivery had no representation.

So the tests that matter most here are not the happy paths. They are:

  - a channel that FAILS is reported as failed, even when another succeeded
  - a channel that was never configured is `skipped`, never `delivered`
  - "nothing reached a person" is said in those words
  - the on-disk record is written even when every network channel dies
  - quiet hours never hold a critical alert
  - no test touches a desktop, a socket, or a mail server

Run: python3 tools/test_alerting.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents import alerting  # noqa: E402
from contracts import Finding  # noqa: E402
from contracts.finding import Coverage  # noqa: E402
from contracts.alert import (  # noqa: E402
    DELIVERED, FAILED, SKIPPED, SUPPRESSED, Alert, Delivery, summarize,
)
from domains.alerting import (  # noqa: E402
    build_alert, in_quiet_hours, normalise_threshold, peak_severity,
    should_deliver, worth_alerting,
)
from engines import notify_desktop, notify_ntfy, notify_smtp  # noqa: E402

passed = 0
NOW = datetime(2026, 7, 27, 3, 14, 0)


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def finding(severity="warning", message="something", fid="f1"):
    return Finding(id=fid, source_module="manual", machine_id="box",
                   severity=severity, confidence="certain", message=message,
                   coverage=Coverage(checked=1, total=1))


def an_alert(severity="warning"):
    return Alert(machine="box", severity=severity, title="t", body="b",
                 raised_at=NOW.isoformat(), finding_ids=["f1"], finding_count=1)


class _Engine:
    """A stand-in channel. NAME matches the real engines' module constant."""

    def __init__(self, name, outcome=DELIVERED, detail=""):
        self.NAME, self._outcome, self._detail = name, outcome, detail
        self.calls = 0

    def send(self, alert, **kwargs):
        self.calls += 1
        return Delivery(self.NAME, self._outcome, self._detail, "target")


class _Exploding:
    def __init__(self, name):
        self.NAME = name

    def send(self, alert, **kwargs):
        raise RuntimeError("engine blew up")


def admin(**overrides):
    cfg = json.loads(json.dumps(alerting.DEFAULT_ADMIN))
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(cfg.get(key), dict):
            cfg[key].update(value)
        else:
            cfg[key] = value
    return cfg


def log_path():
    return os.path.join(tempfile.mkdtemp(), "alerts.log")


# --- the domain: what is worth announcing ---------------------------------

def test_info_never_earns_an_announcement():
    """Same rule as the patrol wrapper, one layer up: churn is not news."""
    check(worth_alerting([finding("info")]) == [], "info is below the bar")
    check(len(worth_alerting([finding("warning")])) == 1, "warning clears it")


class _Event:
    """A severity-carrying object that is NOT a Finding.

    `Finding` validates severity to critical|warning|info, so an unknown one
    cannot reach these functions through that door. It can through others —
    journal events are plain dicts, and `min_severity` is free text from
    data/admin.json — so the defensive ranking still earns its place.
    """

    def __init__(self, severity):
        self.severity, self.id, self.message = severity, "e", "m"


def test_an_unknown_severity_on_an_EVENT_outranks_everything_known():
    """A level this code was never taught must be LOUDER, not quieter."""
    check(len(worth_alerting([_Event("catastrophic")])) == 1,
          "unknown severity is delivered, not filtered out")
    check(peak_severity([finding("critical"), _Event("catastrophic")])
          == "catastrophic", "and it ranks above critical")


def test_a_TYPO_in_min_severity_must_not_silently_mute_everything():
    """The asymmetry that matters, and the bug it prevents.

    An unknown severity ranks above everything. Applied to the THRESHOLD,
    that means nothing ever clears it — so `"min_severity": "urgnet"` in
    data/admin.json would switch off every alert, with no error, no
    delivery, and a console indistinguishable from a quiet network. One
    typo, total silence. The threshold falls back to the default instead.
    """
    check(normalise_threshold("urgnet") == "warning", "a typo falls back")
    check(normalise_threshold("") == "warning", "so does empty")
    check(normalise_threshold("CRITICAL") == "critical", "a real one is honoured")
    check(len(worth_alerting([finding("critical")], "urgnet")) == 1,
          "and a critical finding still gets through a misspelled threshold")


def test_build_alert_returns_none_when_nothing_qualifies():
    check(build_alert([finding("info")], "box", NOW) is None,
          "nothing to announce → None")
    check(build_alert([], "box", NOW) is None, "no findings → None")


def test_build_alert_counts_everything_even_when_it_shows_a_few():
    alert = build_alert([finding("warning", f"m{i}", f"f{i}") for i in range(9)],
                        "box", NOW, max_detail=3)
    check(alert.finding_count == 9, "the true total is carried")
    check("and 6 more" in alert.body, "the hidden ones are stated, not dropped")
    check("not dropped" in alert.body, "and said to be kept")


def test_the_alert_body_does_not_overclaim():
    alert = build_alert([finding("critical", "gateway MAC changed")], "box", NOW)
    check("does not act on the network" in alert.body,
          "it says she proposes and does not act")
    check("not a diagnosis" in alert.body, "and that this is measurement")


# --- quiet hours -----------------------------------------------------------

def test_quiet_hours_wrap_midnight():
    check(in_quiet_hours(datetime(2026, 7, 27, 23, 0), 22, 7), "23:00 is inside 22→7")
    check(in_quiet_hours(datetime(2026, 7, 27, 3, 0), 22, 7), "03:00 is inside 22→7")
    check(not in_quiet_hours(datetime(2026, 7, 27, 12, 0), 22, 7), "noon is outside")
    check(not in_quiet_hours(datetime(2026, 7, 27, 3, 0), None, None),
          "unset means never quiet")


def test_quiet_hours_never_hold_a_critical_alert():
    """04:00 is exactly when a spoofed gateway matters most.

    A 'do not disturb' that silenced it would be this project's founding
    failure wearing a friendly face.
    """
    check(should_deliver(an_alert("critical"), NOW, 22, 7) is True,
          "critical delivers at 03:14 regardless of quiet hours")
    check(should_deliver(an_alert("warning"), NOW, 22, 7) is False,
          "a warning is held")


# --- delivery: the failure paths -------------------------------------------

def test_a_failed_channel_is_reported_even_when_another_succeeds():
    good = _Engine(notify_desktop.NAME)
    bad = _Engine(notify_ntfy.NAME, FAILED, "unreachable")
    out = alerting.deliver(
        an_alert(), admin(desktop={"enabled": True}, ntfy={"enabled": True}),
        NOW, {"desktop": good, "ntfy": bad}, log_path())
    by = {d.channel: d for d in out}
    check(by[notify_desktop.NAME].ok, "the working channel delivered")
    check(by[notify_ntfy.NAME].outcome == FAILED, "the broken one is FAILED")
    check(by[notify_ntfy.NAME].needs_attention,
          "a configured channel that did not carry it needs attention")
    check("FAILED" in summarize(out), "and the summary names it")


def test_an_unconfigured_channel_is_skipped_never_delivered():
    out = alerting.deliver(an_alert(), admin(), NOW,
                           {"desktop": _Engine(notify_desktop.NAME)}, log_path())
    by = {d.channel: d for d in out}
    check(by[notify_ntfy.NAME].outcome == SKIPPED, "ntfy off → skipped")
    check(not by[notify_ntfy.NAME].ok, "skipped is NOT delivered")
    check(not by[notify_ntfy.NAME].needs_attention,
          "but not configuring it is a choice, not a fault")


def test_an_engine_that_raises_becomes_a_failure_not_a_crash():
    """A broken notifier must never take the detector down with it."""
    out = alerting.deliver(an_alert(), admin(ntfy={"enabled": True}), NOW,
                           {"ntfy": _Exploding(notify_ntfy.NAME)}, log_path())
    by = {d.channel: d for d in out}
    check(by[notify_ntfy.NAME].outcome == FAILED, "the raise became a FAILED")
    check("RuntimeError" in by[notify_ntfy.NAME].detail, "and named the cause")


def test_total_failure_says_nobody_was_told():
    alert = an_alert()
    out = alerting.deliver(alert, admin(desktop={"enabled": True}), NOW,
                           {"desktop": _Engine(notify_desktop.NAME, FAILED, "no dbus")},
                           log_path())
    rendered = alerting.render_delivery(alert, out)
    check("NOT DELIVERED" in rendered, "the words 'NOT DELIVERED' appear")
    check("no channel reached a person" in rendered, "stated plainly")


def test_the_disk_record_survives_every_network_channel_dying():
    """The journal is the one record that must not depend on the network.

    This is the case that matters: the LAN is compromised, so outbound
    delivery fails — which is exactly when the evidence must persist.
    """
    path = log_path()
    out = alerting.deliver(
        an_alert("critical"),
        admin(ntfy={"enabled": True}, email={"enabled": True, "host": "h", "to": "t"}),
        NOW,
        {"ntfy": _Engine(notify_ntfy.NAME, FAILED, "unreachable"),
         "email": _Engine(notify_smtp.NAME, FAILED, "timeout")},
        path)
    check(any(d.channel == "journal" and d.ok for d in out), "the journal wrote")
    with open(path, encoding="utf-8") as handle:
        entry = json.loads(handle.readline())
    check(entry["severity"] == "critical", "the alert is on disk")
    check(any(d["outcome"] == FAILED for d in entry["delivery"]),
          "and the disk record states that delivery failed")


def test_quiet_hours_show_as_suppressed_not_delivered():
    out = alerting.deliver(an_alert("warning"),
                           admin(desktop={"enabled": True},
                                 quiet_hours={"start": 22, "end": 7}),
                           NOW, {"desktop": _Engine(notify_desktop.NAME)}, log_path())
    by = {d.channel: d for d in out}
    check(by[notify_desktop.NAME].outcome == SUPPRESSED, "held, not sent")
    check(not by[notify_desktop.NAME].ok, "and held is not delivered")


def test_raise_alert_returns_nothing_when_nothing_qualifies():
    alert, out = alerting.raise_alert([finding("info")], "box", admin(), NOW,
                                      {}, log_path())
    check(alert is None and out == [], "info-only produces no alert")


# --- config ----------------------------------------------------------------

def test_a_missing_admin_file_is_a_state_not_a_crash():
    cfg = alerting.load_admin(os.path.join(tempfile.mkdtemp(), "nope.json"))
    check(cfg["name"] == "", "defaults are returned")
    check(alerting.configured_channels(cfg) == [notify_desktop.NAME],
          "only the free local channel is on by default")


def test_a_corrupt_admin_file_falls_back_rather_than_failing_the_patrol():
    path = os.path.join(tempfile.mkdtemp(), "admin.json")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{ not json")
    check(alerting.load_admin(path)["name"] == "", "bad JSON → defaults, no raise")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
