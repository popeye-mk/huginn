"""Tests for restore verification (R7).

Every test here is about a claim the platform must refuse to make. The
failure mode of backup tooling is not crashing — it is a green tick
meaning "the job ran" being read as "we can recover". So:

- a file restore is never reported as proof of recovery
- a check that could not run never counts as a check that passed
- a broken verifier is ERROR, never FAILED — it says nothing about the backup
- an empty repository fails loudly rather than passing vacuously

The sandbox and restic are faked. That is the point of the engine layer:
this whole flow is testable with no repository, no hypervisor and no
hour of restore time.

Run: python3 tools/test_backup.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import (  # noqa: E402
    RestoreVerification,
    VerificationCheck,
    VerificationDepth,
    VerificationStatus,
)
from domains.backup import VerificationRepository  # noqa: E402
from domains.backup import checks  # noqa: E402
# Fakes (restic + hypervisor) live in backup_fakes so this file carries tests,
# not scaffolding (Theme C — it was seven lines from the 400 hard limit).
from backup_fakes import (  # noqa: E402
    MIN_IMAGE, FakeRestic, FakeSandbox, _service, _snapshot,
)


# --- the claim the contract must refuse -----------------------------------

def test_a_file_restore_is_not_proof_of_recovery():
    """The rule this whole domain exists for."""
    verification = _service().verify("web-02")
    assert verification.status is VerificationStatus.PASSED
    assert verification.depth is VerificationDepth.FILE
    assert verification.is_proof_of_recovery is False
    assert "not a boot test" in verification.summary


def test_a_booted_restore_is_proof_of_recovery():
    verification = _service(sandbox=FakeSandbox()).verify(
        "web-02", boot_test=True
    )
    assert verification.depth is VerificationDepth.BOOT
    assert verification.is_proof_of_recovery is True


def test_passed_cannot_be_constructed_without_checks():
    try:
        RestoreVerification(device_id="web-02", status=VerificationStatus.PASSED)
    except ValueError:
        return
    raise AssertionError("a PASSED verification with no evidence was allowed")


def test_passed_cannot_contradict_a_failing_check():
    try:
        RestoreVerification(
            device_id="web-02",
            status=VerificationStatus.PASSED,
            checks=[VerificationCheck("boot", False, "did not boot")],
        )
    except ValueError:
        return
    raise AssertionError("PASSED with a failing check was allowed")


# --- what the service refuses to claim ------------------------------------

def test_missing_restic_is_not_attempted_not_failed():
    """No tool means no knowledge. It does not mean a bad backup."""
    verification = _service(available=False).verify("web-02")
    assert verification.status is VerificationStatus.NOT_ATTEMPTED
    assert "not installed" in verification.error_message


def test_unconfigured_repository_is_not_attempted():
    verification = _service(configured=False).verify("web-02")
    assert verification.status is VerificationStatus.NOT_ATTEMPTED
    assert "no restic repository" in verification.error_message


def test_an_empty_repository_fails_loudly():
    """The most dangerous state: a job that succeeds nightly on nothing."""
    verification = _service(snapshots=[]).verify("web-02")
    assert verification.status is VerificationStatus.FAILED
    assert any(
        c.name == "snapshot_exists" and not c.passed for c in verification.checks
    )


def test_a_clean_exit_that_restored_nothing_is_a_failure():
    verification = _service(write_bytes=0).verify("web-02")
    assert verification.status is VerificationStatus.FAILED
    restore = [c for c in verification.checks if c.name == "file_restore"][0]
    assert "no data" in restore.detail


def test_a_broken_verifier_is_error_not_failed():
    """ERROR says the check broke; FAILED would blame the backup."""
    service = _service()
    service.restic.snapshots = lambda **kw: (_ for _ in ()).throw(
        RuntimeError("repository unreachable")
    )
    verification = service.verify("web-02")
    assert verification.status is VerificationStatus.ERROR
    assert "unreachable" in verification.error_message


# --- depth is never silently downgraded -----------------------------------

def test_no_sandbox_records_why_it_stayed_shallow():
    verification = _service().verify("web-02", boot_test=True)
    assert verification.depth is VerificationDepth.FILE
    assert "no sandbox available" in verification.depth_limited_by


def test_an_unusable_hypervisor_is_stated_not_hidden():
    verification = _service(sandbox=FakeSandbox(available=False)).verify(
        "web-02", boot_test=True
    )
    assert verification.depth is VerificationDepth.FILE
    assert "not usable" in verification.depth_limited_by


def test_a_backup_with_no_disk_image_cannot_be_boot_tested():
    """The assumption that was never stated, now stated and tested.

    Restic backs up files; booting needs a disk image. A file-level
    backup of a live server would need a bare-metal restore, which this
    platform does not perform — so it stays at file depth and says why,
    rather than failing as though the backup were bad.
    """
    verification = _service(
        sandbox=FakeSandbox(), disk_image=False
    ).verify("web-02", boot_test=True)

    assert verification.depth is VerificationDepth.FILE
    assert verification.status is VerificationStatus.PASSED
    assert "no VM disk image" in verification.depth_limited_by


def test_the_disk_image_is_found_without_being_told_where_it_is():
    """Boot depth must be reachable through the product, not only the API.

    `disk_path` was never supplied by any caller, so this stage could
    previously only be entered from a direct API call. Nothing here
    passes a path.
    """
    verification = _service(sandbox=FakeSandbox()).verify(
        "web-02", boot_test=True
    )
    assert verification.depth is VerificationDepth.BOOT


def test_a_guest_that_boots_then_dies_is_not_a_recovery():
    """The instant of 'running' is when a naive check declares success."""
    verification = _service(
        sandbox=FakeSandbox(stays_up=False)
    ).verify("web-02", boot_test=True)

    stayed = [c for c in verification.checks if c.name == "guest_stayed_up"][0]
    assert stayed.passed is False
    assert verification.status is VerificationStatus.FAILED


def test_a_panicking_console_fails_and_names_what_it_saw():
    verification = _service(
        sandbox=FakeSandbox(console_text="Kernel panic - not syncing: VFS")
    ).verify("web-02", boot_test=True)

    console = [c for c in verification.checks if c.name == "guest_console"][0]
    assert console.passed is False
    assert "kernel panic" in console.detail


def test_an_unreadable_console_is_a_failure_not_a_pass():
    """Absence is never health — including on the way out of the guest."""
    verification = _service(
        sandbox=FakeSandbox(console_available=False)
    ).verify("web-02", boot_test=True)

    console = [c for c in verification.checks if c.name == "guest_console"][0]
    assert console.passed is False
    assert "could not read" in console.detail


def test_a_console_marker_cannot_match_by_coincidence():
    """Found on the first real boot: a Linux guest matched `windows`.

    The verdict was still right — `init:` matched too — but a check that
    can pass on a stray word will eventually pass on nothing else.
    Markers are phrases now, and this is the regression guard.
    """
    verification = _service(
        sandbox=FakeSandbox(console_text="checking display windows and machine")
    ).verify("web-02", boot_test=True)

    console = [c for c in verification.checks if c.name == "guest_console"][0]
    assert console.passed is False, "a coincidental word passed as boot progress"


def test_a_silent_console_is_could_not_confirm_not_confirmed():
    verification = _service(
        sandbox=FakeSandbox(console_text="\x00\x00 garbage")
    ).verify("web-02", boot_test=True)

    console = [c for c in verification.checks if c.name == "guest_console"][0]
    assert console.passed is False
    assert "could not confirm" in console.detail


# --- the guest -------------------------------------------------------------

def test_the_sandbox_is_destroyed_even_when_the_guest_fails():
    """A verifier that leaks VMs gets switched off within a month."""
    sandbox = FakeSandbox(boots=False)
    _service(sandbox=sandbox).verify(
        "web-02", boot_test=True
    )
    assert sandbox.destroyed, "guest was left behind"


# --- checks in isolation ---------------------------------------------------

def test_stale_data_fails_recency():
    old = (datetime.now(timezone.utc) - timedelta(days=40)).isoformat()
    assert checks.data_recency(old, max_age_days=7).passed is False


def test_nanosecond_timestamps_parse():
    """restic emits nanoseconds; fromisoformat accepts microseconds."""
    check = checks.data_recency("2026-07-19T02:00:00.123456789+02:00")
    assert "unreadable" not in check.detail


def test_a_missing_timestamp_fails_rather_than_assuming_fresh():
    assert checks.data_recency("").passed is False


# --- persistence -----------------------------------------------------------

def _repo():
    return VerificationRepository(Path(tempfile.mkdtemp()) / "verifications.db")


def test_never_verified_reads_back_as_none_not_as_a_pass():
    assert _repo().latest_for("web-02") is None


def test_failures_are_kept_not_only_successes():
    repository = _repo()
    for status in (VerificationStatus.FAILED, VerificationStatus.NOT_ATTEMPTED):
        repository.record(
            RestoreVerification(device_id="web-02", status=status)
        )
    assert len(repository.history_for("web-02")) == 2


def test_a_verification_round_trips_with_its_depth_and_checks():
    repository = _repo()
    repository.record(_service().verify("web-02"))

    stored = repository.latest_for("web-02")
    assert stored.depth is VerificationDepth.FILE
    assert stored.is_proof_of_recovery is False
    assert [c.name for c in stored.checks] == [
        "snapshot_exists", "repository_integrity", "data_recency", "file_restore",
    ]


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
