"""Shared PowerShell runner for Windows collectors.

Unverified against a real Windows machine at time of writing (see
README "Known gaps"), but two things here are deliberate rather than
provisional:

**Encoding is forced to UTF-8, not left to the locale.** This is the
single most likely way this tool breaks on a non-English Windows.
`subprocess` with `text=True` decodes using the system's ANSI codepage
(cp1252 on a Western European install, cp1251 on a Cyrillic one). Event
log messages and volume labels routinely contain characters outside
that codepage, and the failure mode is either mojibake inside the JSON
or a hard UnicodeDecodeError that surfaces as a collector "error" with
a confusing reason. The PS preamble sets the output encoding to UTF-8
and we decode as UTF-8 explicitly, with `errors="replace"` so a stray
undecodable byte degrades one character instead of losing the whole
collector. Spec §19 calls for Dutch/French locale testing precisely
because this class of bug is invisible on an English machine.

**A failed command is an `error`, not a `Skip`.** Skip means "this
does not apply here" (no battery, not elevated) and renders as a benign
"Not checked" line. A cmdlet that failed means something went wrong and
the report should say so. Conflating them lets a genuine failure read
as a clean skip, which is the exact shape of mistake §3.4 exists to
prevent. Only a genuinely absent PowerShell is a Skip.
"""

import shutil
import subprocess

from collectors.base import Skip

# Force UTF-8 out of PowerShell regardless of console codepage.
# [Console]::OutputEncoding covers native command output; $OutputEncoding
# covers the pipeline. Both are needed; setting one and not the other is
# a classic half-fix.
ENCODING_PREAMBLE = (
    "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
    "$OutputEncoding = [System.Text.Encoding]::UTF8; "
    "$ProgressPreference = 'SilentlyContinue'; "
)


class PowerShellError(Exception):
    """A PowerShell command failed. Distinct from Skip — see module docstring."""


def run_powershell(command, timeout_s=10):
    exe = shutil.which("pwsh") or shutil.which("powershell")
    if not exe:
        # This one IS a Skip: no PowerShell means these collectors do
        # not apply to this machine at all.
        raise Skip("PowerShell not available on this system")

    proc = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-Command", ENCODING_PREAMBLE + command],
        capture_output=True,
        timeout=timeout_s,
        # Decode ourselves rather than letting text=True pick the locale
        # codepage. errors="replace" degrades one character rather than
        # losing an entire collector to a single bad byte.
        encoding="utf-8",
        errors="replace",
    )

    if proc.returncode != 0:
        raise PowerShellError(f"PowerShell command failed: {(proc.stderr or '').strip()[:200]}")
    if not (proc.stdout or "").strip():
        raise PowerShellError("PowerShell command returned no output")
    return proc.stdout
