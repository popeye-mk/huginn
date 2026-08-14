"""Native shell config (A3 Phase 6) — the small subset of keys ops reads.

Not the fork's 60-key schema: just what the native launcher needs to bind the
server, gate the lean build, and find the GUI + corpus. Defaults ship here; an
optional JSON file overrides them. During the migration the console and corpus
still live under the fork's `ai/anora/data/` (shared data, per the design), so
the defaults point there — they move to native locations only at the final
flip, when `ai/anora/` is retired.
"""

import json
import os

DEFAULTS = {
    "host": "127.0.0.1",                    # loopback; exposure must be explicit
    "port": 8790,
    # The A2 lean-build gate, carried forward.
    "disabled_skills": [
        "user_admin", "approval", "macros", "conversation", "documents",
        "file_search",
    ],
    "console_path": os.path.join("console", "console.html"),
    "dashboard_path": os.path.join("data", "census", "dashboard.html"),
}


def load(path=None):
    """Defaults, overlaid with an optional JSON config file. Never raises."""
    cfg = dict(DEFAULTS)
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                cfg.update(data)
        except (OSError, ValueError):
            pass                            # a broken config file falls back to defaults
    return cfg
