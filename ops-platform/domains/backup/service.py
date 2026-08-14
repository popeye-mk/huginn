"""Backup restore verification — turning a belief into evidence.

The statistic this domain is built around: 82% of backup jobs have
restore testing set to "never", and 31% of organisations fail to recover
despite 92% believing they are covered. Nothing here tries to make
backups better. It tries to make the *claim* honest.

**Verification runs in stages and stops climbing when it runs out of
evidence, never when it runs out of nerve:**

    repository → file → boot

Each stage is deeper than the last, each can be reached or not, and the
result records which one was actually achieved. A machine with no
hypervisor gets a real `file`-level pass with `depth_limited_by` filled
in — not a silent downgrade, and not a `boot` claim it did not earn.

**Nothing here shells out.** Restic and the hypervisor are reached
through engines, which is what lets this whole flow be tested without a
repository, a VM, or an hour of restore time.
"""

import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from contracts import (
    RestoreVerification,
    VerificationCheck,
    VerificationDepth,
    VerificationStatus,
)
from domains.backup import checks
from domains.backup.disk_image import find_disk_image
from engines.restic import ResticEngine

BOOT_TIMEOUT = 300

# How long to let a guest run before asking whether it is still alive.
# A restored system that panics usually does so seconds after the kernel
# loads — a missing storage driver, not a missing bootloader — and the
# moment it reports "running" is exactly when a naive check would call
# it recovered.
DEFAULT_SETTLE_SECONDS = 45


class BackupService:
    """Verifies that a backup can actually be restored."""

    def __init__(
        self,
        restic: Optional[ResticEngine] = None,
        sandbox=None,
        max_age_days: int = checks.DEFAULT_MAX_AGE_DAYS,
        settle_seconds: int = DEFAULT_SETTLE_SECONDS,
    ):
        self.settle_seconds = settle_seconds
        self.restic = restic or ResticEngine()
        # Injected rather than constructed: on a host with no hypervisor
        # there is nothing to construct, and that must be an ordinary
        # shallower result rather than an exception at import time.
        self.sandbox = sandbox
        self.max_age_days = max_age_days

    # -- public ----------------------------------------------------------

    def is_available(self) -> bool:
        return self.restic.is_available()

    def verify(
        self,
        device_id: str,
        host: str = "",
        boot_test: bool = False,
        disk_path: str = "",
    ) -> RestoreVerification:
        """Verify a backup as deeply as this machine allows."""
        started = datetime.now(timezone.utc)

        blocked = self._preflight(device_id)
        if blocked is not None:
            return blocked

        try:
            performed, depth, limited = self._stages(host, boot_test, disk_path)
        except Exception as exc:  # noqa: BLE001
            return self._errored(device_id, exc, started)

        return self._result(device_id, performed, depth, limited, started)

    # -- stages ----------------------------------------------------------

    def _preflight(self, device_id: str) -> Optional[RestoreVerification]:
        """Refuse clearly, before claiming anything about a backup."""
        if not self.restic.is_available():
            return self._not_attempted(
                device_id, "restic is not installed on this machine"
            )
        if not self.restic.is_configured():
            return self._not_attempted(
                device_id,
                "no restic repository configured — nothing to verify",
            )
        return None

    def _stages(self, host: str, boot_test: bool, disk_path: str):
        """Run each stage, returning checks, depth reached, and the limit."""
        performed: List[VerificationCheck] = []
        depth = VerificationDepth.REPOSITORY

        snapshots = self._snapshots(host)
        performed.append(checks.snapshot_exists(snapshots, host))
        integrity = self.restic.check()
        performed.append(
            checks.repository_integrity(integrity.exit_code, integrity.stderr)
        )
        if not snapshots:
            return performed, depth, "repository holds no snapshots"

        newest = snapshots[-1]
        performed.append(
            checks.data_recency(newest.get("time", ""), self.max_age_days)
        )
        snapshot_id = newest.get("short_id") or newest.get("id", "")
        restored, target = self._file_stage(snapshot_id, keep=boot_test)
        performed += restored
        depth = VerificationDepth.FILE

        if not boot_test:
            return performed, depth, "boot test not requested"
        try:
            return self._boot_stage(performed, newest, disk_path, target)
        finally:
            if target is not None:
                shutil.rmtree(target, ignore_errors=True)

    def _file_stage(self, snapshot_id: str, keep: bool = False):
        """Restore into a throwaway directory and measure what arrived.

        Returns `(checks, target)`. When `keep` is False the directory is
        removed immediately — restored data is someone's real files, and
        leaving it in a temp directory is how it ends up inside the next
        backup. The boot stage needs it to survive, so it asks.
        """
        target = Path(tempfile.mkdtemp(prefix="ops-restore-"))
        try:
            output = self.restic.restore(snapshot_id, target)
            performed = [
                checks.file_restore(
                    output.exit_code, _bytes_in(target), output.stderr
                )
            ]
        except Exception:
            shutil.rmtree(target, ignore_errors=True)
            raise

        if not keep:
            shutil.rmtree(target, ignore_errors=True)
            return performed, None
        return performed, target

    def _boot_stage(self, performed, snapshot: dict, disk_path: str, target):
        """Boot the restored disk in a disposable guest, watched from outside."""
        shallow = VerificationDepth.FILE
        if self.sandbox is None:
            return performed, shallow, (
                "no sandbox available on this host — boot not tested"
            )
        if not self.sandbox.is_available():
            return performed, shallow, (
                f"{self.sandbox.kind} is present but not usable "
                f"(administrator rights are typically required)"
            )

        image, reason = self._locate_image(disk_path, target)
        if image is None:
            return performed, shallow, reason

        name = f"ops-verify-{snapshot.get('short_id', 'snapshot')}"
        return performed + self._guest_checks(name, image), (
            VerificationDepth.BOOT
        ), ""

    def _locate_image(self, disk_path: str, target):
        """An explicit image wins; otherwise search what was restored.

        Searching is what makes boot depth reachable through the product
        at all — `disk_path` was never supplied by any caller, so this
        stage could previously only be entered from a direct API call.
        """
        if disk_path:
            return Path(disk_path), ""
        if target is None:
            return None, "nothing was restored, so there is no disk to boot"

        found = find_disk_image(target)
        if not found.found:
            return None, found.reason
        return found.path, ""

    def _guest_checks(self, name: str, image: Path) -> List[VerificationCheck]:
        """Create, boot, watch, destroy — cleanup always runs.

        Nothing is executed inside the guest and no credentials are used.
        A restored production server has whatever was on its disk and a
        password nobody here knows, so every observation is made from
        the host: the hypervisor's view, and the serial console.
        """
        created = self.sandbox.create(name, str(image), memory_mb=2048)
        if created.failed:
            self.sandbox.destroy(name)
            # `.output` carries the hypervisor's own stderr and `.detail`
            # is our summary of it. The first real boot run reported
            # "guest could not be created" and nothing else, because only
            # the summary was read — the same half-a-message mistake
            # already fixed for Diagnostic Companion and for restic.
            return [checks.guest_boot(False, _joined(created))]

        try:
            booted = self.sandbox.boot(name, timeout=BOOT_TIMEOUT)
            results = [checks.guest_boot(booted.ok, booted.detail)]
            if booted.ok:
                results += self._watch(name)
            return results
        finally:
            self.sandbox.destroy(name)

    def _watch(self, name: str) -> List[VerificationCheck]:
        """Let it run, then ask whether it survived and what it said."""
        time.sleep(self.settle_seconds)
        return [
            checks.guest_stayed_up(
                self.sandbox.is_running(name), self.settle_seconds
            ),
            checks.guest_console(self.sandbox.console_log(name)),
        ]

    # -- assembling the record -------------------------------------------

    def _snapshots(self, host: str) -> List[dict]:
        payload = self.restic.snapshots(host=host).payload
        return payload if isinstance(payload, list) else []

    def _result(self, device_id, performed, depth, limited, started):
        failed = [c for c in performed if not c.passed]
        status = (
            VerificationStatus.FAILED if failed else VerificationStatus.PASSED
        )
        return RestoreVerification(
            device_id=device_id,
            status=status,
            depth=depth,
            repository=self.restic.repository,
            checks=performed,
            depth_limited_by=limited,
            started_at=started.isoformat(),
            duration_seconds=_elapsed(started),
        )

    def _not_attempted(self, device_id: str, reason: str) -> RestoreVerification:
        return RestoreVerification(
            device_id=device_id,
            status=VerificationStatus.NOT_ATTEMPTED,
            error_message=reason,
        )

    def _errored(self, device_id, exc, started) -> RestoreVerification:
        """The check broke. That says nothing about the backup, and the
        record must not imply otherwise — ERROR, never FAILED."""
        return RestoreVerification(
            device_id=device_id,
            status=VerificationStatus.ERROR,
            repository=self.restic.repository,
            error_message=f"{type(exc).__name__}: {exc}",
            started_at=started.isoformat(),
            duration_seconds=_elapsed(started),
        )


def _joined(result) -> str:
    """Our summary plus the tool's own words, which name the fix."""
    output = (getattr(result, "output", "") or "").strip()
    if not output:
        return result.detail
    tail = "; ".join(
        line.strip() for line in output.splitlines() if line.strip()
    )[:300]
    return f"{result.detail}: {tail}"


def _bytes_in(directory: Path) -> int:
    """Total size of everything restored, following no symlinks."""
    total = 0
    for path in Path(directory).rglob("*"):
        if path.is_file() and not path.is_symlink():
            try:
                total += path.stat().st_size
            except OSError:
                continue
    return total


def _elapsed(started: datetime) -> float:
    return (datetime.now(timezone.utc) - started).total_seconds()
