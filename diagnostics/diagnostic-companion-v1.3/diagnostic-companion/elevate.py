"""Opt-in privilege escalation (spec §3.1, §14.2).

Drive health is the only check that needs elevation. Everything else
runs unprivileged, and an unprivileged run reports SMART as "could not
check" rather than guessing — which is correct, but means a user who
actually wants drive health has to know to re-run with sudo.

This module offers that as an explicit, explained choice. Three rules
shape it:

**Never escalate silently.** A diagnostic tool that asks for
administrator rights without saying why is indistinguishable from
something you should not run. The menu option says what it needs and
what it will do with it, before any password prompt appears.

**Never escalate by default.** It is a separate menu option, not part
of the normal check. Running as root on a machine that is not yours
should be a decision someone made out loud, not a side effect.

**Fail informatively.** If no escalation mechanism exists, or the user
cancels, say what happened and what the manual command would be. A
cancelled password prompt is a legitimate answer, not an error.

The tool remains read-only when elevated. Elevation grants access to
`smartctl` and the Windows storage reliability counters; it does not
enable anything that writes.
"""

import os
import shutil
import subprocess
import sys

import resources


class ElevationUnavailable(Exception):
    """No mechanism to escalate on this system."""


def is_windows():
    return os.name == "nt"


def already_elevated():
    from collectors.base import is_elevated
    return is_elevated()


def _own_command():
    """The command line that re-invokes this program.

    Frozen: the executable itself. From source: the interpreter plus
    cli.py — using sys.executable rather than "python3" so a venv
    install does not silently escalate into the system interpreter,
    which may not have the dependencies.
    """
    if resources.is_frozen():
        return [sys.executable]
    cli = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cli.py")
    return [sys.executable, cli]


def linux_escalator():
    """Preferred escalation tool, or None.

    pkexec first: it presents a graphical prompt, which is the right
    behaviour when launched from a desktop icon where no terminal may
    be attached to type a sudo password into.
    """
    for tool in ("pkexec", "sudo"):
        path = shutil.which(tool)
        if path:
            return path
    return None


def can_elevate():
    if is_windows():
        return True  # UAC is always present
    return linux_escalator() is not None


def explain():
    """What the caller should tell the user before prompting."""
    if is_windows():
        return ("Windows will ask for permission (a User Account Control "
                "prompt). This is needed to read the disk's own health "
                "counters — nothing is changed.")
    tool = linux_escalator()
    name = os.path.basename(tool) if tool else "sudo"
    return (f"You will be asked for your password ({name}). This is needed "
            "to read the disk's own health data — nothing is changed.")


def run_elevated(args, timeout=180):
    """Re-run this program with `args` under elevation.

    Returns the child's exit code. Raises ElevationUnavailable when
    there is no mechanism to try.
    """
    command = _own_command() + list(args)

    if is_windows():
        return _run_windows_elevated(command, timeout)

    tool = linux_escalator()
    if not tool:
        raise ElevationUnavailable(
            "Neither pkexec nor sudo is available on this system.")

    try:
        return subprocess.call([tool] + command, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124
    except (OSError, KeyboardInterrupt):
        return 130


def _run_windows_elevated(command, timeout):
    """Relaunch through UAC.

    PowerShell's Start-Process -Verb RunAs is the documented way to
    request elevation. -Wait so the caller can report a result, and the
    child keeps its own console so its output is visible rather than
    swallowed.
    """
    exe = command[0]
    rest = command[1:]
    arg_list = ",".join(f"'{a}'" for a in rest) if rest else ""
    argument = f" -ArgumentList {arg_list}" if arg_list else ""

    ps = (f"$p = Start-Process -FilePath '{exe}'{argument} "
          f"-Verb RunAs -Wait -PassThru; exit $p.ExitCode")

    try:
        return subprocess.call(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124
    except (OSError, KeyboardInterrupt):
        return 130


def manual_command_hint(args):
    """What to type by hand if escalation is unavailable or declined."""
    command = " ".join(_own_command() + list(args))
    if is_windows():
        return f'Run an Administrator PowerShell, then:\n      {command}'
    return f"    sudo {command}"
