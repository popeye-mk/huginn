"""Logs collector: last N error-level entries from journalctl (spec §4.1).

Windows counterpart (Get-WinEvent filtered to Error/Critical) is future
work — see Diagnostic_Companion_Next_Steps.md.
"""

import subprocess

from collectors.base import Skip

MAX_ENTRIES = 20


def collect():
    try:
        proc = subprocess.run(
            ["journalctl", "-p", "err", "-n", str(MAX_ENTRIES), "--no-pager", "-o", "short-iso"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except FileNotFoundError:
        raise Skip("journalctl not available on this system")

    if proc.returncode not in (0, 1):
        # journalctl returns 1 in some sandboxed/no-journal environments
        raise Skip(f"journalctl exited {proc.returncode}: {proc.stderr.strip()[:200]}")

    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    return {
        "error_count": len(lines),
        "entries": lines[-MAX_ENTRIES:],
    }
