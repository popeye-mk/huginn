"""Native loopback server (A3 Phase 5) — serves the shell over HTTP.

A lean stdlib `http.server` replacement for the fork's `server.py`, minus the
parts the ops role does not use: no tokens, no PIN, no TTS, no remote sync.
The standing decision is unchanged — **bind 127.0.0.1 by default; no auth only
because of the loopback bind.** Exposing it beyond loopback is the operator's
explicit choice (a different `host`), the same as the fork.

Routes, everything injected so it is testable without globals:
- `GET /`               the console GUI (`console.html`, reused unchanged)
- `GET /api/status`     readiness cells + the LAN/Wi-Fi inventory. Read only;
  there is no POST twin, and adding one is its own decision (see do_GET).
- `GET /guard/dashboard` the guard pane of glass (the file the verb writes)
- `POST /api/command[/stream]` run a line through `dispatch`; the `/stream`
  form answers in the NDJSON `{"type":"done",...}` shape `console.html` reads,
  so the existing GUI needs no change.
"""

import http.server
import json
from urllib.parse import urlparse

from runtime.router import dispatch

_SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    ),
}


class _ShellHandler(http.server.BaseHTTPRequestHandler):
    """Serves the shell. `cfg` (registry/memory/console/dashboard) is set on a
    subclass by `build_handler`, so no single method carries the wiring."""

    cfg = None

    def log_message(self, *args):
        pass                                        # quiet; the console is the log

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in _SEC_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/console"):
            return self._send(200, self.cfg["console"], "text/html; charset=utf-8")
        if path == "/api/admin":
            # Read the registered administrator for the console's settings
            # panel. `redact` is what leaves the process: secrets become
            # booleans, so a browser tab, a screenshot or a devtools panel
            # cannot show the ntfy topic or the mail password.
            from agents.alerting import load_admin, redact
            return self._send(200, json.dumps(redact(load_admin())))
        if path == "/api/status":
            # The console's front page: the four readiness cells and the
            # unified LAN + Wi-Fi inventory, in one read.
            #
            # **READ ONLY, and deliberately so.** There is no POST twin here.
            # Confirming a device or a radio from the browser would need one,
            # and that is a separate decision taken separately — the same care
            # /api/admin got — because it would make a no-auth loopback port
            # able to write the very baseline that decides what counts as an
            # intruder. Seeing more through this port costs nothing: anything
            # that can reach it can already run every verb.
            from agents.surveying import survey
            try:
                return self._send(200, json.dumps(survey()))
            except Exception as exc:            # noqa: BLE001
                # A front page that 500s tells the operator nothing about the
                # network. Answer honestly instead: unread, not healthy.
                return self._send(200, json.dumps(
                    {"ok": False, "state": "unknown", "cells": [],
                     "message": f"the survey itself failed ({type(exc).__name__}) "
                                f"— nothing here was checked"}))
        if path == "/guard/dashboard":
            try:
                with open(self.cfg["dashboard"], "rb") as fh:
                    page = fh.read()
            except OSError:
                page = (b"<!doctype html><meta charset='utf-8'><body>"
                        b"No dashboard yet - run the Dashboard verb first.</body>")
            return self._send(200, page, "text/html; charset=utf-8")
        self._send(404, json.dumps({"ok": False, "message": "not found"}))

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/command", "/api/command/stream", "/api/admin"):
            return self._send(404, json.dumps({"ok": False, "message": "not found"}))
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"

        if path == "/api/admin":
            # Writing settings — including the ntfy topic and the SMTP
            # password — through an endpoint with NO AUTHENTICATION.
            #
            # That is the same standing decision as /api/command, and it
            # rests on the same single fact: this server binds 127.0.0.1.
            # Anything that can reach this port can already run every verb
            # on this machine, so it is not made meaningfully more powerful
            # by also being able to set a notification address. If the bind
            # address ever changes, BOTH endpoints need auth, together —
            # which is why the console shows the live bind address in its
            # footer rather than asserting "local only".
            #
            # The password does not land in admin.json: save_admin writes it
            # to data/secrets/smtp.key at 0600.
            from agents.alerting import save_admin
            try:
                patch = json.loads(raw or b"{}")
            except ValueError:
                return self._send(400, json.dumps(
                    {"ok": False, "message": "malformed JSON"}))
            try:
                saved = save_admin(patch if isinstance(patch, dict) else {})
            except OSError as exc:
                return self._send(500, json.dumps(
                    {"ok": False, "message": f"could not save: {exc}"}))
            return self._send(200, json.dumps({"ok": True, "admin": saved}))

        try:
            text = str(json.loads(raw or b"{}").get("text") or "").strip()
        except ValueError:
            text = ""
        result = dispatch(self.cfg["registry"], text)
        payload = {"ok": result.ok, "message": result.message}
        if path.endswith("/stream"):
            payload["type"] = "done"                # the event console.html reads
            return self._send(200, json.dumps(payload) + "\n",
                              "application/x-ndjson; charset=utf-8")
        self._send(200, json.dumps(payload))


def build_handler(registry, console_html, dashboard_path):
    """A request handler subclass bound to this shell's registry/memory/GUI."""
    cfg = {"registry": registry,
           "console": console_html, "dashboard": dashboard_path}
    return type("ShellHandler", (_ShellHandler,), {"cfg": cfg})


def build_server(registry, console_html, dashboard_path,
                 host="127.0.0.1", port=8790):
    """Bind the loopback server (does not serve yet — caller runs it).

    Returns the `ThreadingHTTPServer`; the launcher calls `serve_forever()`.
    `port=0` binds an ephemeral port (used by the tests).
    """
    handler = build_handler(registry, console_html, dashboard_path)
    return http.server.ThreadingHTTPServer((host, port), handler)
