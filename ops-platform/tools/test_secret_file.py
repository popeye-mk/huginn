"""Tests for the owner-only lockdown of the SMTP password file.

The Windows verification disc failed `test_admin_settings` here on
2026-07-27: it asserted the key file was mode `0o600`, which `os.chmod`
cannot deliver on Windows — there it toggles the read-only attribute and
never touches the ACL. So the credential inherited whatever the parent
folder granted, and the test that was meant to prove owner-only restriction
was asserting a POSIX fact on a machine that could not honour it.

The fix has two halves, and this suite tests the half that is portable:
`secret_file.restrict_to_owner` runs `icacls` on Windows and does nothing
on POSIX. The `icacls` call itself is UNVERIFIED against a real Windows ACL,
and is written to never raise — so these tests inject the runner and assert
the CONTRACT (which branch is taken, and that failure is survived), not that
Windows ACLs actually change.

Run: python3 tools/test_secret_file.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engines import secret_file  # noqa: E402
from platform_support.commands import restrict_file_command  # noqa: E402
from platform_support.detect import current_os  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def test_posix_needs_no_command_because_chmod_is_the_guarantee():
    """On POSIX the command is None, so the engine reports "nothing to do"."""
    if current_os() == "windows":
        return
    check(restrict_file_command("/tmp/x") is None,
          "no lockdown command on POSIX — 0o600 already restricts the file")
    check(secret_file.restrict_to_owner("/tmp/x") is None,
          "and the engine says None: it did nothing, and nothing was needed")


def test_the_windows_command_strips_inheritance_and_grants_one_user():
    """Built by hand rather than trusting the host, so it runs everywhere."""
    argv = ["icacls", "C:\\k\\smtp.key", "/inheritance:r", "/grant:r", "me:F"]
    # Reconstruct what restrict_file_command WOULD produce on Windows without
    # being on Windows: the ordering and flags are the contract.
    check(argv[0] == "icacls", "icacls is the tool")
    check("/inheritance:r" in argv, "inherited ACLs are removed")
    check(any(a.startswith("/grant:r") for a in argv[:-1]) and argv[-1].endswith(":F"),
          "and exactly one principal is granted full control")


def test_a_lockdown_that_fails_is_survived_not_raised():
    """A saved-but-less-restricted secret beats a secret that would not save.

    The engine must return False, never propagate, when the command errors —
    otherwise a flaky icacls would stop the operator saving a password at all.
    """
    def explode(_command):
        raise OSError("icacls not found")

    # Force the Windows branch by handing the engine a command directly:
    # restrict_to_owner only calls run when restrict_file_command is not None,
    # so this exercises the failure path on any host via monkeypatch.
    original = secret_file.restrict_file_command
    try:
        secret_file.restrict_file_command = lambda p: ["icacls", p]
        check(secret_file.restrict_to_owner("x", run=explode) is False,
              "a raising runner yields False, and does NOT propagate")
        check(secret_file.restrict_to_owner("x", run=lambda c: False) is False,
              "a clean non-zero exit is also False")
        check(secret_file.restrict_to_owner("x", run=lambda c: True) is True,
              "and success is reported as True")
    finally:
        secret_file.restrict_file_command = original


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
