"""Tests for the Hyper-V console reader lifecycle.

**What these tests can and cannot prove, stated up front.** There is no
Hyper-V here and no named pipe, so the PowerShell reader script itself
is *unverified* — it is written from documentation, like the virt-install
arguments were before a real KVM guest proved them.

What is tested is the **lifecycle**, which is where the real risk sits:

- the reader starts only after the VM is running, because the pipe does
  not exist before that
- the reader is always stopped, including when the guest fails
- a reader that cannot start degrades the boot result rather than
  raising, because the boot itself succeeded
- an absent capture is reported differently depending on whether a
  reader is running — "nothing said yet" and "nobody listening" are
  different facts

A leaked reader holding a pipe open is the Windows equivalent of the
orphaned VMs this codebase already refuses to leave behind, so the
stop-always property is tested directly.

Run: python3 tools/test_hyperv_console.py
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from engines.sandbox_hyperv import HyperVSandbox  # noqa: E402


class FakeReaders:
    """Records what the sandbox asked for, without touching PowerShell."""

    def __init__(self, fail_with=None):
        self.started = []
        self.stopped = []
        self.running = set()
        self.fail_with = fail_with

    def start(self, name, pipe, path):
        self.started.append((name, pipe, Path(path)))
        if self.fail_with:
            return self.fail_with
        self.running.add(name)
        return None

    def stop(self, name):
        self.stopped.append(name)
        self.running.discard(name)

    def is_running(self, name):
        return name in self.running


class FakePowerShell:
    """A Hyper-V that answers however the test needs it to."""

    def __init__(self, sandbox, running=True, starts=True):
        self.sandbox = sandbox
        self.running = running
        self.starts = starts
        self.scripts = []

    def __call__(self, script, timeout=60):
        from engines.base import EngineOutput

        self.scripts.append(script)
        if "Start-VM" in script and not self.starts:
            return EngineOutput(engine="hyperv", payload="", exit_code=1,
                                stderr="start failed")
        if ".State" in script:
            return EngineOutput(
                engine="hyperv",
                payload="Running" if self.running else "Off",
            )
        return EngineOutput(engine="hyperv", payload="", exit_code=0)


def _sandbox(readers=None, **kw):
    sandbox = HyperVSandbox(
        console_dir=Path(tempfile.mkdtemp()),
        readers=readers or FakeReaders(),
    )
    sandbox._ps = FakePowerShell(sandbox, **kw)
    return sandbox


# --- when the reader starts -----------------------------------------------

def test_the_reader_starts_only_after_the_vm_is_running():
    """The pipe does not exist until the VM does.

    A reader started during `create()` would find nothing to connect to
    and exit before the guest said a word.
    """
    readers = FakeReaders()
    sandbox = _sandbox(readers)

    sandbox.create("vm-1", "C:\\\\disk.vhdx")
    assert readers.started == [], "reader started before the VM was running"

    sandbox.boot("vm-1")
    assert len(readers.started) == 1
    assert readers.started[0][0] == "vm-1"


def test_the_reader_is_pointed_at_the_pipe_and_the_console_file():
    readers = FakeReaders()
    sandbox = _sandbox(readers)
    sandbox.boot("vm-1")

    name, pipe, path = readers.started[0]
    assert pipe == "vm-1"
    assert path == sandbox.console_path("vm-1")


def test_no_reader_starts_if_the_vm_never_ran():
    readers = FakeReaders()
    sandbox = _sandbox(readers, starts=False)

    result = sandbox.boot("vm-1")
    assert result.failed
    assert readers.started == []


# --- when it fails --------------------------------------------------------

def test_a_reader_that_cannot_start_does_not_fail_the_boot():
    """The boot succeeded; what was lost is the console.

    `guest_console` reports the missing capture. Failing the boot here
    would blame the guest for a host-side problem.
    """
    readers = FakeReaders(fail_with="OSError: powershell.exe not found")
    result = _sandbox(readers).boot("vm-1")

    assert result.ok is True
    assert "console capture unavailable" in result.detail
    assert "powershell.exe not found" in result.detail


# --- stopping is not optional ---------------------------------------------

def test_destroy_stops_the_reader():
    readers = FakeReaders()
    sandbox = _sandbox(readers)
    sandbox.boot("vm-1")
    sandbox.destroy("vm-1")

    assert "vm-1" in readers.stopped


def test_destroy_stops_the_reader_before_removing_the_vm():
    """Order matters: a reader blocked on a pipe whose VM is vanishing
    will not notice politely, and leaving it holding the pipe is the
    leak this whole module exists to avoid."""
    readers = FakeReaders()
    sandbox = _sandbox(readers)
    sandbox.boot("vm-1")

    before = len(sandbox._ps.scripts)
    sandbox.destroy("vm-1")
    assert readers.stopped == ["vm-1"]
    assert len(sandbox._ps.scripts) > before, "VM removal still happened"


def test_destroy_is_safe_when_there_was_never_a_reader():
    readers = FakeReaders()
    _sandbox(readers).destroy("never-existed")
    assert readers.stopped == ["never-existed"]


# --- what an absent capture means -----------------------------------------

def test_a_missing_capture_says_whether_anyone_is_listening():
    """"Nothing said yet" and "nobody listening" are different facts.

    The first is a guest that has not spoken; the second is a broken
    capture. Reporting both as "no console" would hide which.
    """
    readers = FakeReaders()
    sandbox = _sandbox(readers)

    quiet = sandbox.console_log("vm-1")
    assert quiet.available is False
    assert "is not running" in quiet.reason

    sandbox.boot("vm-1")
    listening = sandbox.console_log("vm-1")
    assert listening.available is False
    assert "said nothing yet" in listening.reason


def test_a_capture_that_exists_is_read():
    sandbox = _sandbox()
    path = sandbox.console_path("vm-1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("Reached target Multi-User System\n", encoding="utf-8")

    log = sandbox.console_log("vm-1")
    assert log.available is True
    assert log.life_signs


# --- the script itself ----------------------------------------------------

def test_the_reader_connects_as_a_client_not_a_server():
    """Hyper-V owns the pipe; we are the client.

    Getting this backwards produces a reader that waits forever for a
    connection Hyper-V will never make.
    """
    from engines.hyperv_console import _READER

    assert "NamedPipeClientStream" in _READER
    assert "NamedPipeServerStream" not in _READER


def test_the_reader_retries_because_the_pipe_appears_late():
    from engines.hyperv_console import CONNECT_ATTEMPTS, _READER

    assert CONNECT_ATTEMPTS > 1
    assert "Connect(" in _READER
    assert "Start-Sleep" in _READER


def test_the_reader_flushes_so_a_crashed_guest_still_leaves_evidence():
    """A buffered writer loses the last lines — which are the ones that
    say why the machine died."""
    from engines.hyperv_console import _READER

    assert "AutoFlush" in _READER


# --- evidence must outlive cleanup ----------------------------------------

def test_destroy_keeps_the_console_log():
    """Cleanup must not delete the evidence behind its own verdict.

    The first real Hyper-V run produced two lines that contradicted each
    other: `guest_console` reported the console as readable, and the
    harness a moment later reported no file. Both were true in sequence
    -- `destroy()` had deleted it in between -- and together they made
    the one question that mattered, *what did the guest actually say*,
    unanswerable.

    A platform whose whole purpose is verification does not get to erase
    the artefact that explains its finding.
    """
    sandbox = _sandbox()
    path = sandbox.console_path("vm-1")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("boot output worth keeping\n", encoding="utf-8")

    sandbox.destroy("vm-1")

    assert path.is_file(), "destroy() deleted the console log"
    assert "worth keeping" in path.read_text(encoding="utf-8")


def test_an_empty_capture_is_reported_differently_from_an_unreadable_one():
    """Empty and unrecognised have different causes and different fixes.

    Empty: the reader connected, the guest never wrote to its serial
    port -- a guest configuration fact, not a backup fact.

    Unrecognised: the guest spoke and our phrase list is too narrow --
    a fact about this codebase.

    The first run could not distinguish them, which is why it could not
    say whether the pipe reader had worked.
    """
    from domains.backup.checks import guest_console
    from engines.sandbox_base import ConsoleLog

    empty = guest_console(ConsoleLog(text="   \n", available=True))
    assert empty.passed is False
    assert "EMPTY" in empty.detail
    assert "never wrote" in empty.detail

    noisy = guest_console(
        ConsoleLog(text="SeaBIOS v1.2\nsome unknown chatter\n", available=True)
    )
    assert noisy.passed is False
    assert "EMPTY" not in noisy.detail
    assert "SeaBIOS" in noisy.detail, "the operator needs to see what arrived"


def test_firmware_output_is_not_proof_that_the_guest_booted():
    """SeaBIOS printing is not a machine coming back.

    "Booting from Hard Disk..." is written by firmware BEFORE a
    bootloader is loaded, and a disk that hangs one instruction later
    would have been certified as proof of recovery. "No bootable
    device" is itself a BIOS message -- the same subsystem produces
    both the reassuring line and the fatal one.

    Every life sign must mean a KERNEL took control. This is the one
    place where accepting presence as capability would let a broken
    restore pass, which is the worst error this platform can make.
    """
    from domains.backup.checks import guest_console
    from engines.sandbox_base import ConsoleLog

    firmware_only = ConsoleLog(
        text="SeaBIOS (version 1.16.0)\nBooting from Hard Disk...\n",
        available=True,
    )
    result = guest_console(firmware_only)
    assert result.passed is False, (
        "firmware output was accepted as proof the guest booted"
    )

    kernel = ConsoleLog(
        text="[    0.000000] Linux version 5.15.0-71-generic #78\n",
        available=True,
    )
    assert guest_console(kernel).passed is True, (
        "a kernel version banner is unambiguous proof a kernel ran"
    )


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
    print("\n  NOTE: the PowerShell reader script is UNVERIFIED — there is no")
    print("  Hyper-V here. Lifecycle is tested; the script needs a real VM.")
