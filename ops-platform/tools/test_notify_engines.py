"""Tests for the three delivery engines, without touching anything real.

Split from test_alerting.py when it crossed the 400-line hard limit.
test_alerting covers ORCHESTRATION (which channels, in what order, and what
happens when one fails); this covers each engine's own contract.

Every test here injects its transport. No desktop is notified, no socket is
opened, no mail server is contacted — which is the only reason these can run
on the verification disc, on a clean Windows box, offline.

The sharpest one is `test_ntfy_priority_is_an_INT_not_a_string`. Every unit
test passed while the JSON payload carried `"priority": "4"`, because none
of them spoke HTTP; ntfy rejected the first real alert to a real phone with
HTTP 400. Injection keeps tests fast and hermetic, and this is its cost —
it cannot check what the other end thinks of the request.

Run: python3 tools/test_notify_engines.py
"""

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.alert import FAILED, SKIPPED, Alert  # noqa: E402
from engines import notify_desktop, notify_ntfy, notify_smtp  # noqa: E402

passed = 0
NOW = datetime(2026, 7, 27, 3, 14, 0)


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def an_alert(severity="warning"):
    return Alert(machine="box", severity=severity, title="t", body="b",
                 raised_at=NOW.isoformat(), finding_ids=["f1"], finding_count=1)




def test_ntfy_refuses_plaintext_rather_than_downgrading():
    """A plaintext alert channel is worse than a missing one: it looks like
    protection while broadcasting the finding to whoever is on the wire."""
    d = notify_ntfy.send(an_alert(), topic="t", server="http://ntfy.example")
    check(d.outcome == FAILED and "not https" in d.detail, "http is refused")
    check(notify_ntfy.send(an_alert(), topic="t", server="http://x",
                           allow_insecure=True, opener=_fake_opener(200)).ok,
          "unless the operator explicitly allows it")


def test_ntfy_masks_the_topic_in_anything_loggable():
    """The topic IS the secret — anyone holding it receives the alerts."""
    d = notify_ntfy.send(an_alert(), topic="supersecrettopic",
                         opener=_fake_opener(200))
    check("supersecrettopic" not in d.target, "the full topic is not in target")
    check(d.target.startswith("https://ntfy.sh/supe"), "only a stub is shown")


def test_ntfy_unreachable_is_a_failed_delivery():
    import urllib.error

    def boom(*a, **k):
        raise urllib.error.URLError("network is down")

    d = notify_ntfy.send(an_alert(), topic="t", opener=boom)
    check(d.outcome == FAILED and "unreachable" in d.detail,
          "a dead network reads as FAILED, never as 'nothing to report'")


def test_smtp_never_puts_the_password_in_the_result():
    def boom(*a, **k):
        raise OSError("connection refused to user hunter2")

    d = notify_smtp.send(an_alert(), host="h", to_address="a@b",
                         password="hunter2", transport=boom)
    check(d.outcome == FAILED, "the failure is reported")
    check("hunter2" not in d.detail and "hunter2" not in d.target,
          "and the password appears nowhere in it")


def test_smtp_without_config_is_skipped():
    d = notify_smtp.send(an_alert(), host="", to_address="")
    check(d.outcome == SKIPPED, "no host → skipped, not a fake success")


def test_desktop_absent_notify_send_is_skipped_not_failed():
    d = notify_desktop.send(an_alert(), which=lambda _: None)
    check(d.outcome == SKIPPED, "notify-send missing is 'not configured'")


def test_desktop_nonzero_exit_explains_the_usual_cause():
    d = notify_desktop.send(an_alert(), which=lambda _: "/usr/bin/notify-send",
                            run=lambda cmd, timeout: (1, "cannot autolaunch dbus"))
    check(d.outcome == FAILED, "a non-zero exit is a failure")
    check("no desktop session" in d.detail,
          "and names the usual cause, rather than sending the operator hunting")


def _fake_opener(status):
    class _Response:
        def __init__(self):
            self.status = status

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    return lambda *a, **k: _Response()


def test_ntfy_priority_is_an_INT_not_a_string():
    """The bug that broke the first real alert to a real phone.

    ntfy's JSON API types `priority` as a number and rejects the whole
    request with HTTP 400 if it is a string. The header form
    (`X-Priority: 4`) DOES take a string, which is what made the mistake
    easy to make and invisible in every unit test that never spoke HTTP.
    """
    captured = {}

    def opener(request, timeout=None):
        captured["body"] = json.loads(request.data.decode())

        class _R:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return _R()

    notify_ntfy.send(an_alert("critical"), topic="t", opener=opener)
    check(captured["body"]["priority"] == 5, "critical is priority 5")
    check(isinstance(captured["body"]["priority"], int),
          "and it is an int, which is what ntfy's JSON API requires")
    notify_ntfy.send(an_alert("warning"), topic="t", opener=opener)
    check(captured["body"]["priority"] == 4, "warning is 4")


def test_a_rejected_request_reports_ntfys_OWN_reason():
    """A failure you cannot act on is only half reported.

    The first version returned a bare "HTTP 400" and threw the response
    body away — so the operator learned a channel had failed and nothing
    at all about why. ntfy answers with JSON naming the fault.
    """
    import io
    import urllib.error

    def opener(request, timeout=None):
        raise urllib.error.HTTPError(
            "https://ntfy.sh", 400, "Bad Request", {},
            io.BytesIO(b'{"code":40007,"error":"invalid priority",'
                       b'"link":"https://ntfy.sh/docs/publish/#message-priority"}'))

    d = notify_ntfy.send(an_alert(), topic="t", opener=opener)
    check(d.outcome == FAILED, "still a failure")
    check("400" in d.detail, "the status code is kept")
    check("invalid priority" in d.detail, "and ntfy's own reason is carried")


def test_an_unreadable_error_body_still_produces_a_usable_message():
    """The diagnostic must not throw while explaining a failure."""
    import urllib.error

    class _Broken:
        def read(self):
            raise OSError("stream gone")

    def opener(request, timeout=None):
        exc = urllib.error.HTTPError("https://ntfy.sh", 500, "boom", {}, None)
        exc.read = _Broken().read
        raise exc

    d = notify_ntfy.send(an_alert(), topic="t", opener=opener)
    check(d.outcome == FAILED and "500" in d.detail,
          "an unreadable body still yields a reported failure")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
