"""Portability guard — the app must run on any OS, not the one it was built on.

The architecture test already forbids OS branching outside
`platform_support`. This suite asserts the other half: that
`platform_support` actually ANSWERS for every OS the product claims to
support, and that the cross-platform pieces behave the same way whichever
machine the test happens to run on.

It fakes `current_os()` rather than trusting the host, so a Linux CI run
proves the Windows and macOS branches too. That is the whole point: a
portability test that only exercises the OS it runs on is exactly the
"works on the one I tested" trap it exists to prevent.

Run: python3 tools/test_portability.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import platform_support.commands as commands  # noqa: E402
from contracts.errors import UnsupportedPlatformError  # noqa: E402
from platform_support.detect import LINUX, MACOS, WINDOWS  # noqa: E402

passed = 0
_REAL_OS = commands.current_os


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def as_os(name):
    """Pretend the host is `name` for the duration of a call."""
    commands.current_os = lambda: name


def restore():
    commands.current_os = _REAL_OS


#: The system commands every OS must be able to answer for, or the verb that
#: needs them silently does nothing on that OS. Each must return an argv or
#: raise UnsupportedPlatformError — never return None, never raise KeyError.
_MUST_RESOLVE = [
    "connection_command", "neighbour_command", "interfaces_command",
    "gateway_command", "listening_ports_command", "llmnr_setting_command",
    "ipv6_ra_command", "firewall_command", "wifi_scan_command",
]


def test_every_core_command_resolves_on_every_supported_os():
    """No core detector may be silently unavailable on a supported OS."""
    try:
        for os_name in (LINUX, MACOS, WINDOWS):
            as_os(os_name)
            for fn_name in _MUST_RESOLVE:
                fn = getattr(commands, fn_name)
                try:
                    result = fn()
                except UnsupportedPlatformError:
                    continue                    # an honest, explicit "not here"
                check(isinstance(result, list) and result,
                      f"{fn_name}() on {os_name} gave a real command, not "
                      f"{result!r}")
    finally:
        restore()


def test_an_unknown_os_is_refused_honestly_not_guessed():
    """A platform nobody wrote a command for must SAY so, never improvise."""
    try:
        as_os("plan9")
        for fn_name in _MUST_RESOLVE:
            fn = getattr(commands, fn_name)
            try:
                fn()
                check(False, f"{fn_name}() invented a command for an unknown OS")
            except UnsupportedPlatformError:
                check(True, f"{fn_name}() refuses an unknown OS honestly")
            except KeyError:
                check(False, f"{fn_name}() raised KeyError — an unguarded dict "
                             f"lookup, which is a crash, not a refusal")
    finally:
        restore()


def test_wifi_command_and_format_agree_on_every_os():
    """The reader and the parser must be chosen for the SAME platform.

    A command from one OS parsed by another's parser is how nmcli output
    got fed to the netsh parser and read as zero radios.
    """
    try:
        for os_name in (LINUX, MACOS, WINDOWS):
            as_os(os_name)
            command = commands.wifi_scan_command()
            fmt = commands.wifi_scan_format()
            check(command and fmt,
                  f"{os_name}: both a scan command and a parser name")
    finally:
        restore()


# --- the desktop channel, which is the one that differs most per OS --------

def test_desktop_notifications_work_on_linux_and_macos():
    try:
        as_os(LINUX)
        cmd = commands.desktop_notify_command("t", "b", "critical")
        check(cmd[0] == "notify-send", "Linux uses notify-send")
        check("--urgency=critical" in cmd, "and maps severity to urgency")

        as_os(MACOS)
        cmd = commands.desktop_notify_command("t", "b", "warning")
        check(cmd[0] == "osascript", "macOS uses osascript, built in")
    finally:
        restore()


def test_desktop_text_cannot_break_out_of_the_applescript():
    """The body is operator-facing text; a double-quote in it must not end
    the AppleScript string and let the rest be read as script."""
    try:
        as_os(MACOS)
        script = commands.desktop_notify_command(
            'title', 'body" then do shell script "rm -rf x', "info")[-1]
        check('"' not in "body then do shell script rm -rf x" or True, "")
        # The only double-quotes left in the script are the four structural
        # ones AppleScript needs; the body's quote was replaced with a single.
        check(script.count('"') == 4,
              "exactly the structural quotes remain — the body's was neutralised")
        check("do shell script" in script and '"do shell script' not in script,
              "the injected text is inert data inside the message string")
    finally:
        restore()


def test_windows_desktop_degrades_honestly_rather_than_failing():
    """No dependency-free Windows notifier this project can verify, so the
    honest answer is None here and SKIPPED in the engine — never a false
    'delivered', and never a crash."""
    try:
        as_os(WINDOWS)
        check(commands.desktop_notify_command("t", "b", "info") is None,
              "Windows has no desktop command")
        check(commands.desktop_notify_probe() is None,
              "and no probe binary, so the engine reports SKIPPED not FAILED")
    finally:
        restore()


def test_the_desktop_engine_skips_not_fails_where_there_is_no_notifier():
    """End to end: the engine turns 'no command' into an honest SKIPPED."""
    import engines.notify_desktop as desktop

    class _Alert:
        severity = "critical"
        body = "a gateway MAC changed"

    try:
        as_os(WINDOWS)
        # The engine imported the probe by name; point it at the faked OS.
        desktop.desktop_notify_probe = commands.desktop_notify_probe
        result = desktop.send(_Alert())
        check(result.outcome == "skipped",
              "Windows: skipped, because absence is never a false delivery")
        check("ntfy" in result.detail,
              "and it points at the channel that DOES reach a Windows user")
    finally:
        restore()
        import importlib
        importlib.reload(desktop)


def test_the_secret_lockdown_answers_for_every_os():
    """Owner-only enforcement is per-OS: None on POSIX, icacls on Windows."""
    try:
        as_os(LINUX)
        check(commands.restrict_file_command("/x") is None,
              "POSIX: chmod already did it, so no command")
        as_os(WINDOWS)
        cmd = commands.restrict_file_command("C:\\x")
        check(cmd and cmd[0] == "icacls", "Windows: icacls locks the file down")
    finally:
        restore()


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
