"""Which sandbox technology this OS uses — the only place that decides.

Restore verification needs a throwaway machine to restore *into*. On
Linux that is KVM/libvirt; on Windows it is Hyper-V. Those are different
tools with different command surfaces, and the temptation is to write
`if windows:` at the point of use. That is exactly how "runs on both"
becomes "runs on the one I tested".

So this module answers one question — *which kind* — and returns a
string. It deliberately does not import the sandbox classes: engines sit
above platform_support in the layer model, and reaching upward to
instantiate one would invert the whole thing. The factory that maps kind
to class lives in `engines/sandbox_base.py`, where it belongs.
"""

from .detect import LINUX, MACOS, WINDOWS, current_os

KVM = "kvm"
HYPERV = "hyperv"

SANDBOX_KINDS = (KVM, HYPERV)

# One row per OS. Adding macOS support means adding a row and an engine,
# not an `if` somewhere in the backup domain.
_KIND_BY_OS = {
    LINUX: KVM,
    WINDOWS: HYPERV,
    MACOS: None,       # no supported hypervisor wrapper yet — stated, not implied
}


def sandbox_kind() -> str:
    """The sandbox technology for this OS, or "" if there is none.

    Returns empty rather than raising. A machine with no supported
    hypervisor is a normal situation — most admin laptops are one — and
    it should produce a verification recorded as NOT_ATTEMPTED with a
    reason, not an exception that reads like a crash.
    """
    return _KIND_BY_OS.get(current_os()) or ""


def sandbox_unsupported_reason() -> str:
    """Why no sandbox is available here, in words an admin can act on."""
    if sandbox_kind():
        return ""
    return (
        f"no supported hypervisor for {current_os()} — "
        f"boot verification needs KVM (Linux) or Hyper-V (Windows)"
    )
