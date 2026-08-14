"""Tests for the native launcher (A3 Phase 6).

Config load/override, and the real assembly: build_app wires the ops verbs +
corpus + loopback server from config, and the resulting app serves the console
and runs a verb over HTTP — the native shell, launched end to end, no fork.

Run: python3 tools/test_app.py
"""

import json
import os
import sys
import tempfile
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# This suite launches the real app and runs a real verb over HTTP, so it
# passes through `dispatch` and its ownership guard — which claims an
# unclaimed data directory for whichever machine is running. Left pointed at
# the real folder it stakes a claim on the operator's live data under the
# test machine's name. Found by bisection after two other suites had already
# been isolated, which is the argument for the check below in
# test_no_suite_claims_the_real_data_directory: a rule nobody can forget to
# apply beats three files that each remembered.
os.environ["HUGINN_OWNER_FILE"] = os.path.join(tempfile.mkdtemp(), "OWNER.json")

from runtime import config as cfgmod  # noqa: E402
from runtime.app import build_app  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def test_config_defaults_and_override():
    d = cfgmod.load()
    check(d["host"] == "127.0.0.1", "loopback by default")
    check("user_admin" in d["disabled_skills"], "A2 lean gate carried in defaults")
    check(cfgmod.load("/nonexistent/x.json")["port"] == cfgmod.DEFAULTS["port"],
          "a missing config file falls back to defaults")
    path = os.path.join(tempfile.mkdtemp(), "c.json")
    with open(path, "w") as fh:
        json.dump({"port": 9911}, fh)
    check(cfgmod.load(path)["port"] == 9911, "a config file overrides a default")


def test_build_app_assembles_and_serves():
    cfg = cfgmod.load()
    cfg["port"] = 0                              # ephemeral
    httpd, registry = build_app(cfg=cfg)
    check(len(registry.skills) >= 10, "the ops verbs are registered natively")
    check("timeline" in registry.skills, "a known verb is present")

    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(base + "/", timeout=5) as r:
            check(r.status == 200 and "Huginn" in r.read().decode(),
                  "the assembled app serves the real console")
        req = urllib.request.Request(
            base + "/api/command", data=b'{"text":"timeline"}',
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            body = json.loads(r.read().decode())
        check(body["ok"] and "NETWORK GUARD TIMELINE" in body["message"],
              "a real verb runs through the launched app over HTTP")
    finally:
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    test_config_defaults_and_override()
    test_build_app_assembles_and_serves()
    print(f"{passed} tests passed")
