"""Hyper-V sandbox — the Windows restore target.

Same interface as `KvmSandbox`, same rule: **nothing is required inside
the guest, and no credentials are ever held.** An earlier version used
PowerShell Direct (`Invoke-Command -VMName`), which needs a username and
password for the restored machine. That was quietly a bad idea — a
backup verifier that stores guest credentials has created a
credential-management problem in order to solve a recovery-testing one,
and a restored production server is precisely the machine whose password
nobody has to hand.

Everything is observed from outside instead:

- Hyper-V's own view of the VM (`Get-VM`) for running state
- a **COM port redirected to a file on the host** for boot messages

The COM-port file is the equivalent of KVM's serial console. Kernel
panics, `INACCESSIBLE_BOOT_DEVICE` and normal startup all land there
without anyone logging in.

Every cmdlet used here needs administrator rights. Without them the
calls fail with an access error, reported as "could not check" — never
as a failed backup, because blaming a backup for a permissions problem
sends an admin to fix the wrong thing.
"""

from pathlib import Path
from typing import Optional

from engines.base import EngineOutput, run_command
from engines.hyperv_console import ConsoleReaders
from engines.sandbox_base import ConsoleLog, SandboxResult, register_sandbox
from platform_support import HYPERV

POWERSHELL = "powershell.exe"
DEFAULT_MEMORY_MB = 2048
DEFAULT_BOOT_TIMEOUT = 300


class HyperVSandbox:
    """Disposable Hyper-V guest, observed only from the host."""

    kind = HYPERV

    def __init__(
        self,
        powershell: str = POWERSHELL,
        console_dir: Optional[Path] = None,
        readers: Optional[ConsoleReaders] = None,
    ):
        self.powershell = powershell
        self.console_dir = Path(console_dir or Path.home() / "huginn-consoles")
        # Hyper-V publishes the console as a named pipe, which carries
        # nothing unless something listens. These background readers are
        # what make Windows behave like Linux; injectable so the
        # lifecycle can be tested without a hypervisor.
        self.readers = readers if readers is not None else ConsoleReaders(powershell)

    def pipe_name(self, name: str) -> str:
        return name

    def console_path(self, name: str) -> Path:
        return self.console_dir / f"{name}.console.log"

    def _ps(self, script: str, timeout: int = 60) -> EngineOutput:
        return run_command(
            engine=self.kind,
            command=[
                self.powershell, "-NoProfile", "-NonInteractive",
                "-Command", script,
            ],
            timeout=timeout,
            parse_json=False,
        )

    # -- lifecycle -------------------------------------------------------

    def is_available(self) -> bool:
        """Whether the Hyper-V module is present and usable."""
        try:
            result = self._ps(
                "if (Get-Command Get-VM -ErrorAction SilentlyContinue) "
                "{ exit 0 } else { exit 1 }",
                timeout=30,
            )
            return result.exit_code == 0
        except Exception:  # noqa: BLE001
            return False

    def create(
        self,
        name: str,
        disk_path: str,
        memory_mb: int = DEFAULT_MEMORY_MB,
    ) -> SandboxResult:
        """Create a VM around an already-restored VHD/VHDX."""
        disk = Path(disk_path)
        if not disk.is_absolute():
            return SandboxResult(False, "disk path must be absolute")

        self.console_dir.mkdir(parents=True, exist_ok=True)
        console = self.console_path(name)

        result = self._ps(self._create_script(name, disk, memory_mb, console), 180)
        if result.exit_code != 0:
            return SandboxResult(False, "VM could not be created", result.stderr)
        return SandboxResult(True, f"VM {name} created")

    def _create_script(
        self, name: str, disk: Path, memory_mb: int, console: Path
    ) -> str:
        """Generation 1 so the COM port is usable regardless of the guest.

        Generation 2 is the modern default, but its firmware and the
        guests that need it vary in how they surface a serial port. The
        console is the only channel this design has, so it is chosen
        over modernity deliberately.
        """
        return (
            f"New-VM -Name '{name}' -MemoryStartupBytes {memory_mb}MB "
            f"-VHDPath '{disk}' -Generation 1 -ErrorAction Stop | Out-Null; "
            # Disconnected on purpose: a restored image may be
            # compromised and must not reach the admin's network.
            f"Get-VMNetworkAdapter -VMName '{name}' | "
            f"Disconnect-VMNetworkAdapter; "
            f"Set-VMComPort -VMName '{name}' -Number 1 -Path '\\\\.\\pipe\\{name}'; "
            f"Set-VM -Name '{name}' -AutomaticStopAction TurnOff"
        )

    def boot(self, name: str, timeout: int = DEFAULT_BOOT_TIMEOUT) -> SandboxResult:
        """Start the VM and confirm Hyper-V reports it running."""
        started = self._ps(f"Start-VM -Name '{name}' -ErrorAction Stop", 120)
        if started.exit_code != 0:
            return SandboxResult(False, "VM did not start", started.stderr)

        del timeout
        if not self.is_running(name):
            return SandboxResult(False, f"VM is {self.state(name) or 'unknown'}")

        # Started here, not in `create()`: the pipe does not exist until
        # the VM does, so an earlier reader would find nothing to connect
        # to and exit before the guest said a word.
        failure = self.readers.start(
            name, self.pipe_name(name), self.console_path(name)
        )
        if failure:
            # Reported, not raised. The boot itself succeeded; what is
            # lost is the console, and `guest_console` will say so.
            return SandboxResult(
                True, f"VM running (console capture unavailable: {failure})"
            )
        return SandboxResult(True, "VM running")

    def state(self, name: str) -> str:
        result = self._ps(f"(Get-VM -Name '{name}').State", 60)
        return (result.payload or "").strip()

    def is_running(self, name: str) -> bool:
        return self.state(name).lower() == "running"

    def console_log(self, name: str) -> ConsoleLog:
        """Read the COM-port capture, if one exists.

        **Named pipes on Windows are not files that accumulate**, so a
        capture only exists if something is draining the pipe into one.
        When it is absent this returns unavailable with a reason rather
        than an empty string — an empty console and an unread console
        are different facts, and only the first says anything about the
        guest.
        """
        path = self.console_path(name)
        try:
            return ConsoleLog(
                text=path.read_text(encoding="utf-8", errors="replace"),
                available=True,
            )
        except FileNotFoundError:
            running = self.readers.is_running(name)
            return ConsoleLog(
                reason=(
                    f"no COM-port capture at {path} — the pipe reader "
                    + ("is running but the guest has said nothing yet"
                       if running else "is not running")
                )
            )
        except OSError as exc:
            return ConsoleLog(reason=f"console unreadable: {exc}")

    def destroy(self, name: str) -> SandboxResult:
        """Stop and remove the VM, and the reader holding its pipe.

        The reader goes first: a process blocked on a pipe whose VM is
        being torn down is the Windows equivalent of an orphaned guest,
        and this codebase already refuses to leave those behind.
        """
        self.readers.stop(name)
        result = self._ps(
            f"Stop-VM -Name '{name}' -TurnOff -Force "
            f"-ErrorAction SilentlyContinue; "
            f"Remove-VM -Name '{name}' -Force -ErrorAction SilentlyContinue",
            120,
        )
        # The console log is deliberately NOT deleted here.
        #
        # It was, and that destroyed the evidence of the first real run:
        # `guest_console` reported "readable but no recognisable boot
        # progress" while the harness, looking a moment later, reported
        # "no file — the reader never wrote anything". Both were true in
        # sequence and together they were misleading, because the fact
        # that would have settled it — what the guest actually said —
        # had already been erased by cleanup.
        #
        # A platform whose purpose is verification must not delete the
        # only artefact that explains its own verdict. The logs are a
        # few KB, live under the operator's home directory, and the
        # runbook says they are safe to remove.
        if result.exit_code != 0:
            return SandboxResult(False, "VM may still exist", result.stderr)
        return SandboxResult(True, f"VM {name} removed")


register_sandbox(HYPERV, HyperVSandbox)
