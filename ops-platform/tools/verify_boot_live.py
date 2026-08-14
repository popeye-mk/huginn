"""Boot a real guest from a real backup, and check the platform's verdict.

Driven by `verify_boot_live.sh`, which owns restic and the disk image.
This side only calls the platform's own API — the same rule the file-level
harness follows, for the same reason: this platform verifies backups, it
does not create them.

**What this proves that nothing else can.** The `virt-install` arguments,
the serial-console redirection and libvirt's state strings were all
written from documentation. So was every restic detail, and those turned
out correct — but "written carefully" is not "observed working", and the
whole `VerificationDepth.BOOT` idea rests on this path.

Success here is the one claim the contract was built to make: a machine
was restored from a backup and it came back up.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import VerificationDepth, VerificationStatus  # noqa: E402
from domains.backup import BackupService  # noqa: E402
from engines.restic import ResticEngine  # noqa: E402
from engines.sandbox_kvm import KvmSandbox  # noqa: E402


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


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    repository, password_file = sys.argv[1:3]

    sandbox = KvmSandbox()
    if not sandbox.is_available():
        print("    libvirt did not answer on qemu:///session.")
        print("    Try:  virsh --connect qemu:///session version")
        print("    A boot test that cannot run is UNVERIFIED.")
        return 2

    service = BackupService(
        restic=ResticEngine(
            repository=repository, password_file=Path(password_file)
        ),
        sandbox=sandbox,
    )

    print("  booting the restored guest (this takes a minute)")
    verification = service.verify("boot-live-test", boot_test=True)
    print()
    _render(verification)

    return _verdict(verification)


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


if __name__ == "__main__":
    sys.exit(main())
