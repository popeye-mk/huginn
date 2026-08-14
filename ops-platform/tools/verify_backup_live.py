"""Run the backup verifier against a REAL restic repository.

This is the script that closes R7's honest gap. Everything in
`tools/test_backup.py` uses a faked restic: it proves the reasoning —
what the platform claims, refuses to claim, and how it labels depth —
but it proves nothing about the plumbing. The restic JSON shape, the
argument order, the exit codes and the timestamp format were all written
from documentation, and this project has already been bitten once by
trusting documentation over code.

**Driven by `verify_backup_live.sh`, which builds the repository.** That
split is deliberate: the platform verifies backups, it does not create
them, and nothing here should teach it to. The shell script owns restic
init/backup; this file only ever calls the platform's own API.

Two runs, and the second is the one that matters:

1. **A healthy repository** — must come back PASSED at `file` depth,
   with `is_proof_of_recovery` **False** because nothing was booted.
2. **A damaged repository** — must come back FAILED. A verifier that
   only recognises success has not been tested; it has been agreed with.

Usage (via the shell script):
    python3 tools/verify_backup_live.py <repository-path> <password-file>
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import VerificationDepth, VerificationStatus  # noqa: E402
from domains.backup import BackupService  # noqa: E402
from engines.restic import ResticEngine  # noqa: E402


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


def _service(repository: str, password_file: str) -> BackupService:
    return BackupService(
        restic=ResticEngine(
            repository=repository, password_file=Path(password_file)
        )
    )


def healthy(repository: str, password_file: str) -> bool:
    """A working repository must pass — at file depth, not boot depth."""
    print("\n  [1/2] healthy repository")
    verification = _service(repository, password_file).verify("live-test")
    _render(verification)

    problems = []
    if verification.status is not VerificationStatus.PASSED:
        problems.append(f"expected PASSED, got {verification.status.value}")
    if verification.depth is not VerificationDepth.FILE:
        problems.append(f"expected file depth, got {verification.depth.value}")
    if verification.is_proof_of_recovery:
        problems.append(
            "claimed proof of recovery without booting anything — "
            "this is the exact false confidence the contract forbids"
        )
    return _verdict(problems)


def damaged(repository: str, password_file: str) -> bool:
    """A broken repository must fail. The test that actually matters."""
    print("\n  [2/2] damaged repository")
    verification = _service(repository, password_file).verify("live-test")
    _render(verification)

    problems = []
    if verification.status is VerificationStatus.PASSED:
        problems.append(
            "a corrupted repository was reported as PASSED — the verifier "
            "cannot detect a bad backup, which makes it worse than nothing"
        )
    if verification.status is VerificationStatus.NOT_ATTEMPTED:
        problems.append("reported NOT_ATTEMPTED; the repository does exist")
    return _verdict(problems)


def _verdict(problems) -> bool:
    for problem in problems:
        print(f"    !! {problem}")
    print(f"    => {'OK' if not problems else 'WRONG'}")
    return not problems


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__)
        return 2

    mode, repository, password_file = sys.argv[1:4]
    engine = ResticEngine(
        repository=repository, password_file=Path(password_file)
    )
    if not engine.is_available():
        print("  restic is not installed — see verify_backup_live.sh")
        return 2

    runner = {"healthy": healthy, "damaged": damaged}.get(mode)
    if runner is None:
        print(f"  unknown mode {mode!r}; expected 'healthy' or 'damaged'")
        return 2
    return 0 if runner(repository, password_file) else 1


if __name__ == "__main__":
    sys.exit(main())
