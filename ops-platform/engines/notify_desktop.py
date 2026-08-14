"""Desktop notification engine — a toast on THIS machine.

The zero-trust channel: no network, no credentials, nothing stored. It
reaches the operator only when they are at the machine, which is exactly
why it is never the only channel — but it costs nothing, so it is always
attempted.

**Cross-platform, the same way everything else here is.** The engine does
not know how to raise a toast on any particular OS. It asks
`platform_support` for the command and runs it — Linux gets `notify-send`,
macOS gets `osascript`, and Windows gets None, because there is no
dependency-free notifier this project can verify there. Windows therefore
degrades to SKIPPED with a pointer to ntfy, which every OS can use; it does
NOT fail, and it never pretends to have shown something it did not.

Engine-layer because it shells out, which by this codebase's rules may
only happen here.
"""

import shutil
import subprocess
from typing import Optional

from contracts.alert import DELIVERED, FAILED, SKIPPED, Delivery
from platform_support.commands import (
    desktop_notify_command,
    desktop_notify_probe,
)

NAME = "desktop"
DEFAULT_TIMEOUT = 10


def is_available(which=None) -> bool:
    """True only if THIS OS has a desktop notifier and the tool is present.

    Two ways to be unavailable, and the caller is told which: the OS has no
    known mechanism (Windows), or it has one whose tool is not installed (a
    headless Linux without libnotify).
    """
    probe = desktop_notify_probe()
    if probe is None:
        return False
    return (which or shutil.which)(probe) is not None


def send(alert, run=None, which=None, timeout: int = DEFAULT_TIMEOUT) -> Delivery:
    """Show a desktop toast. `run`/`which` are injectable for tests.

    Never raises: a notifier that crashed the patrol that called it would
    turn a detection into an outage.
    """
    if desktop_notify_probe() is None:
        return Delivery(NAME, SKIPPED,
                        "no desktop notifier on this OS — use ntfy to be "
                        "reached here", "this desktop")
    if not is_available(which):
        return Delivery(NAME, SKIPPED,
                        f"{desktop_notify_probe()} is not installed",
                        "this desktop")

    command = desktop_notify_command(
        f"Huginn — {alert.severity}", alert.body, alert.severity)
    runner = run or _run
    try:
        code, err = runner(command, timeout)
    except Exception as exc:                        # noqa: BLE001
        return Delivery(NAME, FAILED, f"{type(exc).__name__}: {exc}", "this desktop")

    if code != 0:
        # The usual cause on Linux is no D-Bus session — i.e. running from a
        # systemd timer with no desktop attached. Say that, because "failed"
        # alone sends the operator hunting.
        hint = err.strip() or "no message"
        return Delivery(NAME, FAILED,
                        f"exit {code}: {hint} (no desktop session?)", "this desktop")
    return Delivery(NAME, DELIVERED, "", "this desktop")


def _run(command, timeout):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return result.returncode, (result.stderr or "")
