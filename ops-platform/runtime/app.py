"""Native launcher (A3 Phase 6) — assembles and runs the shell, no fork.

`build_app` wires config → a registry of the ops verbs and the loopback
server; `main` serves it. This is the entry point:

    python3 -m runtime.app        # start the shell on the loopback port

It replaced `anora.py`, the vendored fork's launcher, which was archived to
`../attic/anora-fork-20260726/` on 2026-07-26. There is no second launcher
to fall back to and no vendored code left to host — this is the product.
"""

import os
from datetime import datetime

from runtime import config as _config
from runtime.registry import SkillRegistry, auto_discover, failure_report
from runtime.server import build_server

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

_STAMP_SKIP = {".git", "__pycache__", "data", "attic", "node_modules"}


def _read(path, fallback):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return fallback


def build_stamp(root=None, now=None):
    """A value that CHANGES when the code moves or the server restarts.

    The console footer carries this next to the words "if this doesn't change
    after a restart, the server is stale". It was the literal placeholder
    `__BUILD_STAMP__` that nothing ever substituted, so the field could never
    have kept that promise — it would have looked identical whether you had
    restarted or not. That is precisely the "absence looks like health"
    failure this project exists to refuse, committed by the one widget meant
    to catch a stale server, so it is a real reading now:

    - `code <newest .py mtime>` is sampled when the process boots. Edit a
      file without restarting and this still shows the OLD time — which is
      the tell that the running server is not your latest code.
    - `up <start time>` proves the restart actually happened.

    No subprocess and no git: a stamp that needed a tool present would go
    blank on the machines where being sure matters most.
    """
    root = root or _ROOT
    newest = 0.0
    for base, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _STAMP_SKIP]
        for name in files:
            if name.endswith(".py"):
                try:
                    newest = max(newest, os.path.getmtime(os.path.join(base, name)))
                except OSError:
                    pass                    # unreadable file: skip, never crash boot
    now = now or datetime.now()
    code = datetime.fromtimestamp(newest).strftime("%m-%d %H:%M") if newest else "unknown"
    return f"code {code} · up {now.strftime('%H:%M:%S')}"


def build_app(cfg=None, skills_dir=None):
    """Assemble the shell: (httpd, registry). Paths resolve against the repo."""
    cfg = cfg or _config.load()
    skills_dir = skills_dir or os.path.join(_ROOT, "skills")
    registry = SkillRegistry()
    auto_discover(registry, skills_dir, disabled_modules=cfg.get("disabled_skills"))

    console = _read(os.path.join(_ROOT, cfg["console_path"]),
                    "<!doctype html><title>Huginn</title><body>console.html not found</body>")
    console = console.replace("__BUILD_STAMP__", build_stamp())
    dashboard_path = os.path.join(_ROOT, cfg["dashboard_path"])
    httpd = build_server(
        registry, console, dashboard_path,
        host=cfg.get("host", "127.0.0.1"), port=int(cfg.get("port", 8790)),
    )
    return httpd, registry


def main():
    httpd, registry = build_app()
    host, port = httpd.server_address
    print(f"Huginn (native shell) — {len(registry.skills)} verbs — "
          f"http://{host}:{port}")
    # A verb that failed to load is a verb the operator still believes they
    # have. Four of them (backup, devices, history, threat) were missing from
    # this shell for a day after the fork was archived, with buttons for them
    # still on the console, because discovery swallowed the failure.
    report = failure_report(registry)
    if report:
        print(report)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
