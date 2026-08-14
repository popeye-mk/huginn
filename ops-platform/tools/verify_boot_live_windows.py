"""Boot a real Hyper-V guest from a real backup, and check the verdict.

Driven by `verify_boot_live_windows.ps1`, which owns restic and the disk
image. This side only calls the platform's own API — the same split the
Linux pair follows, for the same two reasons: this platform verifies
backups rather than creating them, and `subprocess` belongs in `engines/`
(the architecture test enforces both, and caught the first draft of this
file doing it wrong).

**What this proves that nothing else can.** The PowerShell named-pipe
reader in `engines/hyperv_console.py` has never touched a real pipe. Its
lifecycle is tested — starts only after the VM runs, always stopped,
degrades rather than crashes — but the script itself was written from
documentation. So were the `virt-install` arguments before a real KVM
guest proved them, and one of those turned out wrong (`--osinfo`).

Expect the same odds. A failure here is a finding, not a setback.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import VerificationDepth, VerificationStatus  # noqa: E402
from domains.backup import BackupService  # noqa: E402
from engines.restic import ResticEngine  # noqa: E402
from engines.sandbox_hyperv import HyperVSandbox  # noqa: E402

DEVICE_ID = "boot-live-test"


def _elevated() -> bool:
    """Every Hyper-V cmdlet used here needs administrator rights.

    Checked here as well as in the script, because the failure mode
    otherwise is a wall of access-denied text that reads like a broken
    backup rather than a missing privilege.
    """
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _render(verification) -> None:
    print(f"    status   {verification.status.value}")
    print(f"    depth    {verification.depth.value}")
    print(f"    proof    {verification.is_proof_of_recovery}")
    if verification.depth_limited_by:
        print(f"    limited  {verification.depth_limited_by}")
    if verification.error_message:
        print(f"    error    {verification.error_message}")
    for check in verification.checks:
        mark = "pass" if check.passed else "FAIL"
        print(f"    [{mark}] {check.name:22} {check.detail}")
    print(f"    summary  {verification.summary}")


def _console_tail(sandbox: HyperVSandbox) -> None:
    """Show the console capture, whatever came of it.

    This is the entire point of the run. If the reader worked, the proof
    is here; if it did not, the reason is here — and either way it is
    worth more than the pass/fail line above it.
    """
    # The guest is named after the SNAPSHOT (`ops-verify-<short_id>`),
    # not after the device. This harness previously looked up
    # `console_path(DEVICE_ID)` and reported "no file" twice — a path
    # that was never going to exist, while the real capture sat beside
    # it under another name. Both times the message read as a finding
    # about the reader. It was a finding about this function.
    #
    # So: read the directory, do not predict the filename.
    print()
    directory = sandbox.console_dir
    logs = sorted(
        directory.glob("*.console.log"), key=lambda p: p.stat().st_mtime
    ) if directory.is_dir() else []

    if not logs:
        print(f"  console capture: nothing under {directory}")
        print("    The check above ran first and is the authority on what")
        print("    the console contained.")
        return

    path = logs[-1]
    print(f"  console capture: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        print("    FILE IS EMPTY — the reader ran but the guest said nothing.")
        print("    Cirros may not be writing to COM1 under Generation 1.")
        return
    lines = text.splitlines()
    print(f"    {len(lines)} line(s) captured. Last 20:")
    for line in lines[-20:]:
        print(f"      | {line}")


def _verdict(verification) -> int:
    problems = []
    if verification.depth is not VerificationDepth.BOOT:
        problems.append(
            f"never reached boot depth (stayed at {verification.depth.value}) — "
            f"{verification.depth_limited_by or 'no reason recorded'}"
        )
    if verification.status is not VerificationStatus.PASSED:
        problems.append(f"status was {verification.status.value}, not passed")
    if not verification.is_proof_of_recovery:
        problems.append("did not qualify as proof of recovery")

    print()
    for problem in problems:
        print(f"    !! {problem}")
    print(f"    => {'PROOF OF RECOVERY' if not problems else 'NOT PROVEN'}")
    return 0 if not problems else 1


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    repository, password_file = sys.argv[1:3]

    if not _elevated():
        print("    NOT RUNNING AS ADMINISTRATOR.")
        print("    Hyper-V cmdlets will fail with access errors that look")
        print("    like verification failures. Open PowerShell with Win+X, A.")
        return 2

    sandbox = HyperVSandbox()
    if not sandbox.is_available():
        print("    Hyper-V did not answer.  Check:  Get-VMHost")
        print("    A boot test that cannot run is UNVERIFIED.")
        return 2

    service = BackupService(
        restic=ResticEngine(
            repository=repository, password_file=Path(password_file)
        ),
        sandbox=sandbox,
    )

    print("  booting the restored guest (this takes a minute)")
    try:
        verification = service.verify(DEVICE_ID, boot_test=True)
        print()
        _render(verification)
        _console_tail(sandbox)
        return _verdict(verification)
    finally:
        # An orphaned VM holding a named pipe open is precisely the leak
        # this design refuses to leave behind. Belt and braces: the
        # service destroys its own guest; this catches the case where it
        # could not.
        sandbox.destroy(DEVICE_ID)


if __name__ == "__main__":
    sys.exit(main())
