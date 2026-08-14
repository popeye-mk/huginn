"""Portable / USB-stick operation (spec §20, §14.5).

The intended workflow: a technician carries `diag.exe` on a USB stick,
plugs it into a machine that is misbehaving, runs it, and walks away
with a report. Three things have to be true for that to work.

**Reports must land next to the executable, not in the current
directory.** When a user double-clicks an exe from Explorer the working
directory is often `C:\\Windows\\System32` or the user's profile —
nowhere near the stick. A report saved there is effectively lost, and
worse, it has been written to the client's machine, which a read-only
diagnostic tool should avoid doing by accident.

**Reports must be named per machine.** A fixed `report.html` means the
second machine of the day silently overwrites the first. On a support
round that is a real loss of work, and it fails quietly.

**It must degrade to something sensible.** A stick can be
write-protected, and some managed machines block writes to removable
media. Falling back to the user's home directory and *saying so* beats
either crashing or silently writing somewhere unexpected.

`sys.executable` points at the .exe itself in PyInstaller's onefile
mode (not at the temp extraction directory), so it is the correct
anchor for "beside the program".
"""

import os
import re
import sys
from datetime import datetime

from resources import is_frozen


def program_dir():
    """Directory containing the running program.

    Frozen: the folder holding the executable — the USB stick.
    Source: the repository, so development behaves predictably.
    """
    if is_frozen():
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _writable(path):
    if not os.path.isdir(path):
        return False
    probe = os.path.join(path, f".diag_write_test_{os.getpid()}")
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("")
        os.remove(probe)
        return True
    except OSError:
        return False


def output_dir():
    """Where reports should be written. Returns (path, fell_back).

    Prefers the program's own directory so a USB stick collects its own
    reports. Falls back to the user's home directory when that is not
    writable — a write-protected stick, or a machine that blocks writes
    to removable media. The caller is expected to mention the fallback
    rather than let the file appear somewhere unexplained.
    """
    preferred = program_dir()
    if _writable(preferred):
        return preferred, False

    fallback = os.path.expanduser("~")
    return fallback, True


def safe_hostname(hostname):
    """Make a hostname safe for a filename on any platform.

    Hostnames are usually tame, but this one goes straight into a path
    and the value came off the machine being diagnosed, so it is not
    trusted (§13).
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", str(hostname or "unknown")).strip("-.")
    return (cleaned or "unknown")[:60]


def report_filename(hostname, extension="html", when=None):
    """`DESKTOP-ABC_2026-07-20_1142.html` — sorts chronologically per machine."""
    when = when or datetime.now()
    return f"{safe_hostname(hostname)}_{when:%Y-%m-%d_%H%M}.{extension}"


def report_path(hostname, extension="html", when=None):
    """Full path for a new report. Returns (path, fell_back)."""
    directory, fell_back = output_dir()
    return os.path.join(directory, report_filename(hostname, extension, when)), fell_back


def existing_reports(limit=10):
    """Previous reports sitting beside the program, newest first.

    Lets the menu show what has already been collected on this round
    without the user going hunting in Explorer.
    """
    directory, _ = output_dir()
    try:
        names = [n for n in os.listdir(directory)
                 if n.endswith((".html", ".json")) and "_" in n]
    except OSError:
        return []

    paths = [os.path.join(directory, n) for n in names]
    paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return paths[:limit]
