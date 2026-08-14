"""Interactive menu (spec §14.2, §14.5).

Launched automatically when the packaged binary is run with no
arguments — which is what happens when someone double-clicks it from
Explorer or a USB stick. Without this, argparse prints usage text and
the console window closes before anyone can read it.

**Written to be read by the person whose machine it is**, not only by
the technician running it. That constraint drives most of the choices
here:

* No jargon in the menu itself. "Check this computer", not "run
  collectors". The detailed report still uses precise language — this
  is the front door, not a dumbing-down of the diagnosis.
* No emoji and no colour-only signalling (§14.2). Same rules as every
  other terminal surface; a client's machine may have any console.
* Every action states what it is about to do, and the tool's read-only
  nature is stated on the front screen. Someone watching a stranger run
  software on their computer deserves to know it only reads.
* Nothing destructive is reachable from here. `diag fix` is absent by
  design even in dry-run form — a menu is the wrong place to introduce
  the one command that could change something.

The menu never invents its own diagnosis. Every option calls the same
code paths as the command line, so what a client sees on screen and
what a technician gets from `diag run` cannot diverge.
"""

import os
import sys

import console
import elevate
import portable

RULE = "=" * 66


def _say(text=""):
    console.write(text)


def _prompt(text):
    """Read a line, treating Ctrl+C / Ctrl+D / closed stdin as 'quit'."""
    try:
        return input(text).strip()
    except (EOFError, KeyboardInterrupt):
        _say()
        return "q"


def _pause():
    _prompt("\nPress Enter to return to the menu... ")


def _header():
    _say()
    _say(RULE)
    _say("  DIAGNOSTIC COMPANION")
    _say(RULE)
    _say("  This tool only reads information from this computer.")
    _say("  It does not change anything, install anything, or send")
    _say("  anything anywhere.")
    _say(RULE)


def _menu_text():
    # Option 3 is listed only when it would actually do something: on
    # a machine that is already elevated, drive health is included in
    # option 1 and offering to "also" check it would be nonsense.
    drive_line = ""
    if not elevate.already_elevated():
        drive_line = "  3   Check the drive's health too (asks for your password)\n"

    return f"""
  1   Check this computer now
  2   Check this computer and save a report I can send on
{drive_line}
  4   Explain a Windows error code
  5   Show what has already been checked today
  6   Save this computer as "known good" for comparing later
  7   Compare this computer against its "known good" state

  q   Quit
"""


def run_menu(argv_runner):
    """Drive the menu. `argv_runner` executes a CLI argument list.

    The runner is injected rather than imported so the menu cannot
    accumulate its own logic: every option is literally a command line,
    which keeps this screen and the documented commands in step.
    """
    while True:
        _header()
        _say(_menu_text())

        choice = _prompt("  Choose an option: ").lower()

        if choice in ("q", "quit", "exit", "0"):
            _say("\n  Done. Nothing on this computer was changed.\n")
            return 0

        if choice == "1":
            _say("\n  Checking this computer. This takes about half a minute.\n")
            argv_runner(["simple"])
            _say("\n  A fuller technical report is available from option 2.")
            _pause()

        elif choice == "2":
            _save_report(argv_runner)

        elif choice == "3":
            _check_with_drive_health(argv_runner)

        elif choice == "4":
            _decode(argv_runner)

        elif choice == "5":
            _list_reports()

        elif choice == "6":
            _say("\n  Recording the current state as the reference point.")
            _say("  Nothing is changed - this only remembers how things look now.\n")
            argv_runner(["baseline"])
            _pause()

        elif choice == "7":
            _say("\n  Comparing against the saved reference point.\n")
            code = argv_runner(["run", "--diff"])
            if code == 1:
                _say("\n  If this says no reference point was saved, use option 5 first.")
            _pause()

        else:
            _say("\n  Sorry, I did not recognise that. Please type a number "
                 "from the list, or q to quit.")
            _pause()


def _check_with_drive_health(argv_runner):
    """Re-run elevated so the drive's own health data can be read.

    Deliberately a separate, labelled option. Escalating as part of the
    ordinary check would mean a tool run on someone else's machine asks
    for administrator rights without anyone having decided to allow it.
    """
    if elevate.already_elevated():
        _say("\n  This is already running with the rights it needs, so")
        _say("  option 1 includes the drive check.\n")
        argv_runner(["simple"])
        _pause()
        return

    _say()
    _say("  Everything except drive health can be checked without special")
    _say("  permission. Reading the drive's own health data needs more.")
    _say()
    _say(f"  {elevate.explain()}")
    _say()
    _say("  The tool still only reads. Nothing is installed or changed.")
    _say()

    answer = _prompt("  Continue? (y/N): ").lower()
    if answer not in ("y", "yes"):
        _say("\n  Left as it was. Option 1 checks everything else.")
        _pause()
        return

    if not elevate.can_elevate():
        _say("\n  This system has no way to ask for those rights.")
        _say("  To check the drive, run this by hand:\n")
        _say(elevate.manual_command_hint(["run"]))
        _pause()
        return

    _say("\n  Asking for permission...\n")
    code = elevate.run_elevated(["simple"])

    if code == 130:
        _say("\n  Cancelled. Nothing was run.")
    elif code == 124:
        _say("\n  Timed out waiting for permission. Nothing was run.")
    elif code not in (0, 1, 2):
        _say("\n  Could not get those rights. To check the drive by hand:\n")
        _say(elevate.manual_command_hint(["run"]))
    _pause()


def _save_report(argv_runner):
    import socket

    hostname = socket.gethostname()
    path, fell_back = portable.report_path(hostname, "html")

    _say(f"\n  Checking this computer and writing a report to:\n    {path}\n")
    if fell_back:
        _say("  (The program's own folder is not writable - possibly a")
        _say("   read-only USB stick - so the report goes to your home")
        _say("   folder instead.)\n")

    argv_runner(["run", "--format", "html", "-o", path])

    if os.path.isfile(path):
        size = os.path.getsize(path)
        _say(f"\n  Saved: {os.path.basename(path)}  ({size:,} bytes)")
        _say("  This is a single file. It can be emailed or copied as-is,")
        _say("  and opens in any web browser without needing this program.")
    else:
        _say("\n  The report could not be written. The folder may be read-only.")
    _pause()


def _decode(argv_runner):
    _say("\n  Type the error code exactly as it appeared, for example")
    _say("  0x80070005 or 0x7E. Press Enter on its own to go back.\n")

    code = _prompt("  Error code: ")
    if not code:
        return

    _say()
    result = argv_runner(["decode", code])
    if result != 0:
        _say("\n  That code is not in this tool's list. That does not mean")
        _say("  it is harmless - only that there is nothing useful to say")
        _say("  about it here.")
    _pause()


def _list_reports():
    reports = portable.existing_reports()
    directory, _ = portable.output_dir()

    _say(f"\n  Reports saved in:\n    {directory}\n")
    if not reports:
        _say("  None yet. Use option 2 to create one.")
    else:
        for path in reports:
            size = os.path.getsize(path)
            _say(f"    {os.path.basename(path):<48} {size:>9,} bytes")
    _pause()


def should_auto_launch(argv, frozen):
    """True when the menu is the right response to how we were started.

    Only when packaged, given no arguments, and attached to a real
    console. Running from source with no arguments still prints help,
    because a developer typing `python cli.py` wants usage, not a menu.
    Piped or redirected invocations must never block on input.
    """
    if not frozen or argv:
        return False
    try:
        return bool(sys.stdin and sys.stdin.isatty() and sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False
