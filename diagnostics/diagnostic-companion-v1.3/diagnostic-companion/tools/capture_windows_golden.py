#!/usr/bin/env python3
"""
Run this ON THE WINDOWS MACHINE you want to test against (Win11 or
Windows Server) — it's the missing piece the collectors/windows/*.py
modules have never been checked against (see README's "Known gaps").

What it does, for each of the 4 Windows collectors:
  1. Runs the actual PowerShell command the collector uses.
  2. Prints the RAW output exactly as PowerShell returned it.
  3. Feeds that raw output through the collector's parse() function.
  4. Prints either the parsed result or the full traceback if parsing
     failed — so a broken assumption is visible immediately instead of
     silently swallowed as a Skip/error status.

It also writes everything to windows_capture_output.txt next to this
script, so the whole run can be copied/pasted or attached in one piece
without scrolling back through a terminal.

No admin rights required. Nothing is changed on the machine — this only
runs the same read-only queries `diag run` would run.
"""

import io
import json
import sys
import traceback
from contextlib import redirect_stdout

sys.path.insert(0, __file__.rsplit("tools", 1)[0])  # repo root, so `collectors` imports work

from collectors.windows import disk, logs, network, system  # noqa: E402
from collectors.windows._powershell import run_powershell  # noqa: E402

COLLECTORS = [
    ("system", system),
    ("disk", disk),
    ("network", network),
    ("logs", logs),
]


def capture_one(name, module):
    print(f"\n{'=' * 70}\n{name}\n{'=' * 70}")

    print("\n--- PowerShell command ---")
    print(module.PS_COMMAND)

    print("\n--- raw output ---")
    try:
        raw = run_powershell(module.PS_COMMAND, timeout_s=20)
        print(raw)
    except Exception:
        print("RAW CAPTURE FAILED:")
        traceback.print_exc()
        return

    print("\n--- parse() result ---")
    try:
        parsed = module.parse(raw)
        print(json.dumps(parsed, indent=2, default=str))
    except Exception:
        print("PARSE FAILED:")
        traceback.print_exc()


def print_environment():
    """Facts that explain most parse failures before the parse is even read.

    PowerShell major version changes ConvertTo-Json's behaviour, and the
    console codepage is the difference between clean UTF-8 and mojibake
    on a non-English install (spec §19).
    """
    import locale
    import platform as _platform

    print("=" * 70)
    print("environment")
    print("=" * 70)
    print(f"python:          {sys.version.split()[0]}")
    print(f"platform:        {_platform.platform()}")
    print(f"preferred enc:   {locale.getpreferredencoding(False)}")

    try:
        from collectors.base import is_elevated
        print(f"elevated:        {is_elevated()}")
    except Exception as e:
        print(f"elevated:        unknown ({e})")

    probe = (
        "$PSVersionTable.PSVersion.ToString() + '|' + "
        "[System.Globalization.CultureInfo]::CurrentUICulture.Name + '|' + "
        "(Get-Culture).Name + '|' + [Console]::OutputEncoding.WebName"
    )
    try:
        raw = run_powershell(probe, timeout_s=15).strip()
        version, ui_culture, culture, encoding = (raw.split("|") + ["?"] * 4)[:4]
        print(f"powershell:      {version}")
        print(f"UI culture:      {ui_culture}   (event log message language)")
        print(f"culture:         {culture}")
        print(f"console enc:     {encoding}")
    except Exception:
        print("powershell probe FAILED:")
        traceback.print_exc()
    print()


def main():
    buf = io.StringIO()

    class Tee:
        def write(self, s):
            sys.__stdout__.write(s)
            buf.write(s)

        def flush(self):
            sys.__stdout__.flush()

    with redirect_stdout(Tee()):
        print("Diagnostic Companion — Windows collector capture")
        print("Run this output back to the person who's fixing the Windows collectors.\n")
        print_environment()
        for name, module in COLLECTORS:
            capture_one(name, module)

    out_file = "windows_capture_output.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(buf.getvalue())
    print(f"\n\nFull output also written to: {out_file}")


if __name__ == "__main__":
    main()
