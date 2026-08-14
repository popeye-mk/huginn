"""Incident snapshot (H2) — freeze the evidence while it still exists.

The problem this solves: the guard alerts at 03:00, the operator looks at 08:00,
and by then the ARP cache has aged out, the attacker's lease has been renewed,
and the connection that mattered has closed. **Volatile evidence has a
half-life measured in minutes.** Everything the guard reads — neighbour table,
DHCP lease, routes, connections, listening ports — is live state, not history.

So: one command that captures all of it at a single moment, writes it to a
timestamped file, and prints a short readable summary. Fast (no scans, no
network probes — only reads of state this host already holds), so it can be run
*while* something is happening, and cheap enough for the patrol to trigger
automatically the moment it raises an alert.

This domain only **arranges** what the caller collected; the reads live in the
engines. That keeps it pure, testable, and free of subprocess.
"""

import json
import os
from datetime import datetime, timezone


def build_snapshot(machine_id, captured_at, sections):
    """One incident record: what was true, on which machine, at what moment."""
    return {
        "machine": machine_id,
        "captured_at": captured_at,
        "sections": {k: v for k, v in (sections or {}).items()},
    }


def _count(value):
    if isinstance(value, (list, tuple, dict)):
        return len(value)
    if value is None:
        return None
    return 1


def render_summary(snapshot, path=""):
    """The short human read — what was captured, what was empty, where it went."""
    sections = snapshot.get("sections") or {}
    lines = [f"  INCIDENT SNAPSHOT — {snapshot.get('machine', '?')}",
             "  " + "=" * 58,
             f"  Captured {snapshot.get('captured_at', '?')}", ""]
    for name in sorted(sections):
        count = _count(sections[name])
        if count is None:
            lines.append(f"   ? {name:22} not readable — NOT an all-clear")
        elif count == 0:
            lines.append(f"   - {name:22} nothing seen")
        else:
            lines.append(f"   • {name:22} {count} item(s)")
    if path:
        lines += ["", f"  Written to: {path}",
                  "  (Volatile state ages out fast — this is the copy that "
                  "will still be true tomorrow.)"]
    return "\n".join(lines)


def save_snapshot(directory, snapshot):
    """Write the snapshot under a timestamped name. Returns the path."""
    os.makedirs(directory, exist_ok=True)
    stamp = str(snapshot.get("captured_at") or "").replace(":", "").replace("-", "")
    stamp = stamp.replace("+0000", "Z")[:15] or datetime.now(
        timezone.utc).strftime("%Y%m%dT%H%M%S")
    path = os.path.join(directory, f"incident-{stamp}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(snapshot, fh, indent=1, ensure_ascii=False, default=str)
    os.replace(tmp, path)
    return path
