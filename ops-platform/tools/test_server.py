"""Integration tests for the native loopback server (A3 Phase 5).

Starts the real server on an ephemeral 127.0.0.1 port and drives every route
over HTTP: the console GUI, the command endpoint (plain + the NDJSON stream
form console.html reads), a grounded question, the dashboard route, and 404.
Loopback only — no third-party client, just urllib.

Run: python3 tools/test_server.py
"""

import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# See test_router.py: every request here goes through `dispatch`, which
# claims an unclaimed data directory for the machine running it. Point that
# somewhere disposable, or the suite stakes a claim on the operator's live
# folder under the test machine's name.
import os  # noqa: E402
import tempfile  # noqa: E402
os.environ["HUGINN_OWNER_FILE"] = os.path.join(tempfile.mkdtemp(), "OWNER.json")

from runtime.registry import SkillRegistry  # noqa: E402
from runtime.server import build_server  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


_CONSOLE = "<!doctype html><title>Huginn</title><body>console</body>"


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=5) as r:
        return r.status, r.read().decode("utf-8")


def _post(base, path, obj):
    req = urllib.request.Request(base + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read().decode("utf-8")


def _check_status_route(base):
    """The console's front page feed, and the fact that it only reads.

    A POST twin here would let a port with NO AUTHENTICATION rewrite the
    very baseline that decides what counts as an intruder. That may one day
    be worth doing, but it should never happen by accident: if someone adds
    it, this fails, and they have to mean it.
    """
    status, body = _get(base, "/api/status")
    payload = json.loads(body)
    check(status == 200 and "cells" in payload,
          "GET /api/status feeds the console's status strip")
    check(payload.get("state") in ("ok", "attention", "unknown"),
          "and reports one of the three states, never a bare boolean")
    try:
        _post(base, "/api/status", {"anything": True})
        check(False, "unreachable")
    except urllib.error.HTTPError as e:
        check(e.code == 404, "POST /api/status is refused — reads only")


def _run_all():
    reg = SkillRegistry()
    reg.register("ping", lambda args, sp=None: f"PONG[{args}]")
    httpd = build_server(reg, _CONSOLE, "/nonexistent/dash.html",
                         host="127.0.0.1", port=0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        status, body = _get(base, "/")
        check(status == 200 and "console" in body, "GET / serves the console GUI")

        status, body = _post(base, "/api/command", {"text": "ping now"})
        data = json.loads(body)
        check(data["ok"] and data["message"] == "PONG[now]", "POST /api/command runs the verb with args")

        status, body = _post(base, "/api/command/stream", {"text": "ping"})
        ev = json.loads(body.strip())
        check(ev.get("type") == "done" and ev["message"] == "PONG[]",
              "stream form returns the NDJSON 'done' event console.html reads")

        status, body = _post(base, "/api/command", {"text": "how do I configure dhcp scope"})
        payload = json.loads(body)
        check(payload["ok"] is False and "do not answer general questions" in payload["message"],
              "a non-verb is refused honestly (answering retired 2026-07-26)")

        _check_status_route(base)

        status, body = _get(base, "/guard/dashboard")
        check(status == 200 and "No dashboard yet" in body,
              "dashboard route serves the honest placeholder when no file exists")

        try:
            _get(base, "/nope")
            check(False, "unreachable")
        except urllib.error.HTTPError as e:
            check(e.code == 404, "unknown route → 404")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_server_routes():
    _run_all()


if __name__ == "__main__":
    _run_all()
    print(f"{passed} tests passed")
