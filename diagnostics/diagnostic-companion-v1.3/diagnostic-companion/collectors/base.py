"""
Collector runner: wraps every collector function so timeout, privilege
and error handling are enforced in one place instead of per-collector
(spec §3.3 "every collector declares a timeout", §3.4 "absence is never
health").

Known v0 limitation: a ThreadPoolExecutor timeout does not forcibly
kill a genuinely hung syscall (e.g. a wedged ioctl to a dying disk) —
CPython can't interrupt a blocked C call from another thread. The spec
(§3.3) calls for a subprocess-per-collector model with a hard kill for
exactly this reason ("smartctl against a failing drive can block for
minutes"). That's the right v1 fix; v0 uses threads to keep the proof
of concept simple and notes the gap here rather than hiding it.
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError

from schema import build_envelope


class Skip(Exception):
    """Raise from a collector to mark it as cleanly not-applicable / not-privileged."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def is_elevated():
    """True if running as root (POSIX) or Administrator (Windows).

    Windows path is untested — no Windows box in this build environment
    (see Diagnostic_Companion_Next_Steps.md). Written defensively so it
    fails closed (reports not-elevated) rather than raising.
    """
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def require_privilege(level):
    """Call at the top of a collector that needs elevation. Raises Skip
    with a clean, spec-consistent reason string (§3.1) if not met."""
    if level == "elevated" and not is_elevated():
        raise Skip("insufficient_privileges: requires root/Administrator")


def run_collector(name, func, timeout_s=10, privilege_level="unprivileged"):
    start = time.monotonic()
    status, reason, data = "error", "unknown error", {}

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(func)
        try:
            data = future.result(timeout=timeout_s)
            status, reason = "ok", None
        except FutureTimeoutError:
            status = "timeout"
            reason = f"{name} did not complete within {timeout_s}s"
            data = {}
        except Skip as e:
            status = "skipped"
            reason = e.reason
            data = {}
        except Exception as e:  # noqa: BLE001 - a collector must never crash the run
            status = "error"
            reason = f"{type(e).__name__}: {e}"
            data = {}

    duration_ms = int((time.monotonic() - start) * 1000)
    return build_envelope(status, reason, duration_ms, privilege_level, data)
