"""Sandbox interface — a throwaway machine to restore a backup into.

Restoring a backup over the machine you are trying to protect is not a
test, it is an outage. So verification always happens inside a disposable
guest: create, boot, run checks, destroy.

**The interface is the same on both operating systems; only the
implementations differ** (`sandbox_kvm.py`, `sandbox_hyperv.py`). Which
one to build is decided by `platform_support.sandbox_kind()` and nowhere
else — this module maps that answer to a class and does no OS detection
of its own.

Three properties every implementation must hold, because breaking any of
them turns a safety tool into a hazard:

1. **Never touch the host.** All writes go to paths the sandbox created.
2. **Always clean up**, including after a failure — a verification that
   leaves orphaned VMs will be switched off within a month.
3. **Never report a guest as healthy because a check could not run.**
   Absence is not health, in here as everywhere else.

4. **Require nothing to be installed inside the guest.** A restored
   production server contains whatever was on the disk, and this
   platform will not have its credentials. Everything observed is
   observed from outside: the hypervisor's own view of the domain, and
   the serial console it attaches.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol

from contracts.errors import UnsupportedPlatformError


@dataclass
class SandboxResult:
    """Outcome of one sandbox operation."""

    ok: bool
    detail: str = ""
    output: str = ""

    @property
    def failed(self) -> bool:
        return not self.ok


@dataclass
class ConsoleLog:
    """What the guest said on its serial console.

    **The only channel into a restored guest that requires nothing to be
    installed in it.** The original design ran a health command inside
    the guest over qemu-guest-agent or PowerShell Direct — which meant
    the guest needed an agent, or this platform needed its credentials.
    Neither is true of a restored production server: you get whatever
    was on the disk, and you very likely do not have its password.

    A serial console is attached from outside by the hypervisor, so
    boot messages are readable without cooperation from the guest. It is
    a narrower signal than running a diagnostic inside — and narrow and
    obtainable beats rich and hypothetical.
    """

    text: str = ""
    available: bool = False
    reason: str = ""

    # Phrases that indicate a boot got far enough to be worth calling a
    # boot. Deliberately not a promise that the machine is *well*.
    #
    # **Each one is a phrase, not a word.** The first real boot run
    # passed a Cirros Linux guest partly on the marker `windows`, which
    # matched something incidental in its console. The verdict was still
    # correct — `init:` matched too — but a check that can pass on a
    # coincidence is a check that will eventually pass on nothing else.
    # Same failure as the knowledge base scoring "coffee machine" against
    # three security entries, and the fix is the same: require enough
    # specificity that a stray match cannot happen.
    LIFE_SIGNS = (
        "reached target", "login:", "systemd[1]", "init: ",
        "starting kernel", "freeing unused kernel",
        "microsoft windows", "welcome to",
        # A kernel version banner is the earliest unambiguous proof that
        # a kernel took control of the machine. Missing it cost a real
        # Hyper-V run: the guest wrote
        #     [    0.000000] Linux version 5.15.0-71-generic ...
        # and the platform called that "no recognisable boot progress",
        # reporting our narrow vocabulary as the guest's silence.
        #
        # These stay phrases, not words. The word "windows" alone once
        # matched a Cirros Linux guest.
        # Every one of these means a KERNEL took control. Firmware
        # banners are deliberately absent: "SeaBIOS v1.2" is printed by
        # a machine with no bootable disk at all, and "no bootable
        # device" is itself a BIOS message. Firmware ran is not the
        # guest booted -- presence is not capability, in the one place
        # where accepting it would let an unbootable restore pass.
        #
        # Caught by this project's own test, which offered SeaBIOS as an
        # example of UNRECOGNISED output and started failing the moment
        # "bios" was added to this list.
        "linux version", "kernel command line", "booting the kernel",
    )
    # Substrings that mean the boot definitively failed.
    FAILURES = (
        "kernel panic", "not syncing", "unable to mount root",
        "no bootable device", "operating system not found",
        "attempted to kill init", "inaccessible boot device",
    )

    def _matches(self, needles) -> List[str]:
        lowered = (self.text or "").lower()
        return [n for n in needles if n in lowered]

    @property
    def failures(self) -> List[str]:
        return self._matches(self.FAILURES)

    @property
    def life_signs(self) -> List[str]:
        return self._matches(self.LIFE_SIGNS)


class Sandbox(Protocol):
    """What every sandbox implementation provides."""

    kind: str

    def is_available(self) -> bool:
        """Whether this hypervisor can be driven right now."""
        ...

    def create(self, name: str, disk_path: str, memory_mb: int) -> SandboxResult:
        ...

    def boot(self, name: str, timeout: int) -> SandboxResult:
        ...

    def is_running(self, name: str) -> bool:
        """Whether the guest is still up. Used to catch boot loops."""
        ...

    def console_log(self, name: str) -> ConsoleLog:
        """Serial console output captured from outside the guest."""
        ...

    def destroy(self, name: str) -> SandboxResult:
        ...


_REGISTRY: Dict[str, type] = {}


def register_sandbox(kind: str, cls: type) -> None:
    """Register an implementation against the kind it serves."""
    _REGISTRY[kind] = cls


def create_sandbox(kind: str = "", **kwargs) -> Sandbox:
    """Build the sandbox for this machine.

    `kind` is normally omitted and resolved from `platform_support`;
    passing it explicitly exists for tests, which must be able to
    exercise the Hyper-V path from Linux without pretending to be
    Windows.
    """
    from platform_support import SANDBOX_KINDS, current_os, sandbox_kind

    resolved = kind or sandbox_kind()
    if not resolved:
        raise UnsupportedPlatformError(
            "restore sandbox", current_os(), SANDBOX_KINDS
        )

    # Imported here rather than at module scope so that registration
    # happens on demand and a broken implementation for one OS cannot
    # stop the other from loading.
    from engines import sandbox_hyperv, sandbox_kvm  # noqa: F401

    try:
        cls = _REGISTRY[resolved]
    except KeyError:
        raise UnsupportedPlatformError(
            f"restore sandbox ({resolved})", current_os(), tuple(_REGISTRY)
        ) from None
    return cls(**kwargs)
