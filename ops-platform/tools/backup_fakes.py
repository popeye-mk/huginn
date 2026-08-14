"""Fakes for the backup tests — a restic and a hypervisor that never existed.

Extracted from `test_backup.py` (Theme C) so the test file carries tests, not
~100 lines of scaffolding — it was seven lines from the 400 hard limit. These
fakes are the point of the engine layer: the whole verify flow is testable
with no repository, no hypervisor and no hour of restore time.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.backup import BackupService  # noqa: E402
from engines.base import EngineOutput  # noqa: E402
from engines.sandbox_base import ConsoleLog, SandboxResult  # noqa: E402

MIN_IMAGE = 17 * 1024 * 1024


def _snapshot(days_old=1, short_id="ab12cd34"):
    when = datetime.now(timezone.utc) - timedelta(days=days_old)
    return {"short_id": short_id, "id": short_id * 4, "time": when.isoformat()}


class FakeRestic:
    """A restic that answers without a repository."""

    def __init__(self, snapshots=None, check_code=0, restore_code=0,
                 available=True, configured=True, write_bytes=1024,
                 disk_image=True):
        self.repository = "/tmp/fake-repo" if configured else ""
        self._snapshots = snapshots if snapshots is not None else [_snapshot()]
        self._check_code = check_code
        self._restore_code = restore_code
        self._available = available
        self.write_bytes = write_bytes
        self.disk_image = disk_image

    def is_available(self):
        return self._available

    def is_configured(self):
        return bool(self.repository)

    def snapshots(self, host="", timeout=0):
        return EngineOutput(engine="restic", payload=self._snapshots)

    def check(self, read_data_percent=0, timeout=0):
        return EngineOutput(
            engine="restic", payload="", exit_code=self._check_code,
            stderr="" if not self._check_code else "pack file damaged",
        )

    def restore(self, snapshot_id, target, include=None, timeout=0):
        if self._restore_code == 0 and self.write_bytes:
            (Path(target) / "restored.bin").write_bytes(b"x" * self.write_bytes)
            if self.disk_image:
                # A backup of a VM disk. Large enough to clear the
                # placeholder floor in disk_image.py.
                (Path(target) / "server.qcow2").write_bytes(
                    b"\0" * (17 * 1024 * 1024)
                )
        return EngineOutput(
            engine="restic", payload="", exit_code=self._restore_code,
            stderr="" if not self._restore_code else "repository is locked",
        )


class FakeSandbox:
    """A hypervisor that never existed, observed the way a real one is.

    Note what it does NOT have: `run_in_guest`. Boot verification no longer
    executes anything inside the guest, so the fake cannot either — a fake
    that offers a capability the real thing has stopped providing is how
    tests keep passing after the product changed.
    """

    kind = "fake"

    def __init__(self, available=True, boots=True, stays_up=True,
                 console_text="Reached target Multi-User System",
                 console_available=True):
        self._available = available
        self._boots = boots
        self._stays_up = stays_up
        self._console_text = console_text
        self._console_available = console_available
        self.destroyed = []

    def is_available(self):
        return self._available

    def create(self, name, disk_path, memory_mb=2048):
        return SandboxResult(True, "created")

    def boot(self, name, timeout=300):
        return SandboxResult(self._boots, "running" if self._boots else "kernel panic")

    def is_running(self, name):
        return self._stays_up

    def console_log(self, name):
        if not self._console_available:
            return ConsoleLog(reason="no console capture")
        return ConsoleLog(text=self._console_text, available=True)

    def destroy(self, name):
        self.destroyed.append(name)
        return SandboxResult(True, "destroyed")


def _service(**kwargs):
    sandbox = kwargs.pop("sandbox", None)
    return BackupService(
        restic=FakeRestic(**kwargs), sandbox=sandbox, settle_seconds=0
    )
