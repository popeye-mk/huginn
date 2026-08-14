"""KVM/libvirt sandbox — the Linux restore target.

Drives `virt-install` and `virsh` rather than libvirt's Python bindings:
both are present wherever libvirt is, need no compiled extension, and
keep every external call inside `engines.base.run_command`.

**Nothing is required inside the guest.** An earlier version executed a
health command over qemu-guest-agent, which meant a restored production
server had to already have the agent installed — it will not. Everything
here is observed from outside: libvirt's own view of the domain, and a
**serial console redirected to a file on the host**, which is how boot
messages become readable without the guest cooperating.

The console file is the whole trick. `kernel panic`, `no bootable
device` and `reached target Multi-User System` all arrive on it, and
none of them need a login.
"""

from pathlib import Path
from typing import List, Optional

from engines.base import EngineOutput, run_command
from engines.sandbox_base import ConsoleLog, SandboxResult, register_sandbox
from platform_support import KVM

VIRSH = "virsh"
VIRT_INSTALL = "virt-install"
DEFAULT_MEMORY_MB = 2048
DEFAULT_BOOT_TIMEOUT = 300


class KvmSandbox:
    """Disposable KVM guest, observed only from the host."""

    kind = KVM

    def __init__(
        self,
        virsh: str = VIRSH,
        virt_install: str = VIRT_INSTALL,
        connection: str = "qemu:///session",
        console_dir: Optional[Path] = None,
    ):
        self.virsh = virsh
        self.virt_install = virt_install
        # `qemu:///session` rather than `system`: a per-user libvirt
        # instance needs no root, and a backup verifier that demands root
        # is a backup verifier that gets run less often.
        self.connection = connection
        self.console_dir = Path(console_dir or "/tmp")

    # -- helpers ---------------------------------------------------------

    def console_path(self, name: str) -> Path:
        return self.console_dir / f"{name}.console.log"

    def _virsh(self, *args, timeout: int = 60) -> EngineOutput:
        return run_command(
            engine=self.kind,
            command=[self.virsh, "--connect", self.connection,
                     *[str(a) for a in args]],
            timeout=timeout,
            parse_json=False,
        )

    # -- lifecycle -------------------------------------------------------

    def is_available(self) -> bool:
        """Whether libvirt answers. Never raises — absence is an answer."""
        try:
            return self._virsh("version", timeout=15).exit_code == 0
        except Exception:  # noqa: BLE001
            return False

    def create(
        self,
        name: str,
        disk_path: str,
        memory_mb: int = DEFAULT_MEMORY_MB,
    ) -> SandboxResult:
        """Define and start a transient guest around a restored disk."""
        disk = Path(disk_path)
        if not disk.is_absolute():
            return SandboxResult(False, "disk path must be absolute")
        if not disk.is_file():
            return SandboxResult(False, f"disk image not found: {disk}")

        console = self.console_path(name)
        console.unlink(missing_ok=True)

        result = run_command(
            engine=self.kind,
            command=self._install_args(name, disk, memory_mb, console),
            timeout=180,
            parse_json=False,
        )
        if result.exit_code != 0:
            return SandboxResult(False, "guest could not be created", result.stderr)
        return SandboxResult(True, f"guest {name} created")

    def _install_args(
        self, name: str, disk: Path, memory_mb: int, console: Path
    ) -> List[str]:
        """How the disposable guest is shaped.

        `--import` boots the disk as-is with no installer. `--transient`
        means the definition vanishes when it stops, so a crash of this
        process cannot leave a permanent VM on the admin's hypervisor.
        """
        return [
            self.virt_install,
            "--connect", self.connection,
            "--name", name,
            "--memory", str(memory_mb),
            "--disk", f"path={disk},format=qcow2",
            "--import",
            "--transient",
            "--noautoconsole",
            "--graphics", "none",
            # virt-install 4.x refuses to run without an OS hint. That
            # is reasonable for installs and wrong for us: the disk came
            # out of someone's backup and we do not know what is on it —
            # that is the question, not the input. `detect=on,require=off`
            # says guess if you can and proceed if you cannot.
            "--osinfo", "detect=on,require=off",
            # No network. A machine restored from a backup may be
            # compromised; verification must not put it on the LAN.
            "--network", "none",
            # The channel this whole design rests on: boot messages to a
            # file the host can read without entering the guest.
            "--serial", f"file,path={console}",
        ]

    def boot(self, name: str, timeout: int = DEFAULT_BOOT_TIMEOUT) -> SandboxResult:
        """Confirm libvirt reports the guest running.

        `virt-install --import` starts it, so this reads state rather
        than starting anything — separate step because "created" and
        "running" are different claims.
        """
        del timeout
        state = self.state(name)
        if state != "running":
            return SandboxResult(False, f"guest is {state or 'unknown'}, not running")
        return SandboxResult(True, "guest running")

    def state(self, name: str) -> str:
        result = self._virsh("domstate", name, timeout=30)
        if result.exit_code != 0:
            return ""
        return (result.payload or "").strip()

    def is_running(self, name: str) -> bool:
        return self.state(name) == "running"

    def console_log(self, name: str) -> ConsoleLog:
        """Read whatever the guest has printed to its serial console."""
        path = self.console_path(name)
        try:
            return ConsoleLog(
                text=path.read_text(encoding="utf-8", errors="replace"),
                available=True,
            )
        except FileNotFoundError:
            return ConsoleLog(reason=f"no console log at {path}")
        except OSError as exc:
            return ConsoleLog(reason=f"console unreadable: {exc}")

    def destroy(self, name: str) -> SandboxResult:
        """Stop and remove the guest. Safe to call when it never existed."""
        stopped = self._virsh("destroy", name, timeout=60)
        # Transient domains disappear on stop; undefine is attempted
        # anyway because "usually" is not a cleanup guarantee, and
        # orphaned VMs are how an admin stops trusting a tool.
        self._virsh("undefine", name, timeout=60)
        # The console log survives teardown, deliberately. Deleting it
        # here erased the evidence behind a real Hyper-V verdict, and the
        # same line was sitting in this file waiting to do the same on
        # Linux — it simply never bit, because a passing run needs no
        # explanation. `create()` still clears the log before each run,
        # which is the deletion that matters: a stale capture read as
        # this run's output would be far worse than a kept one.

        stderr = (stopped.stderr or "").lower()
        if stopped.exit_code != 0 and "not found" not in stderr:
            return SandboxResult(False, "guest may still exist", stopped.stderr)
        return SandboxResult(True, f"guest {name} removed")


register_sandbox(KVM, KvmSandbox)
