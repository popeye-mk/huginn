"""Engine output → VerificationCheck. Pure functions, no I/O.

Every check here answers one question and says which one it answered.
That matters more than it sounds: the failure mode of backup tooling is
a green tick that means "the job ran", and a green tick that means "the
data came back" is a different claim entirely. Naming each check after
the claim it supports is what keeps the two apart in the report.

Kept separate from `service.py` so the interpretation of a tool's output
can be read, tested and argued about without a repository, a hypervisor
or an hour of restore time.
"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional

from contracts import VerificationCheck

# A backup that is fine but three weeks old is not a working backup for
# most businesses. The threshold is generous by design — it exists to
# catch jobs that silently stopped, not to nag about schedule drift.
DEFAULT_MAX_AGE_DAYS = 7


def repository_integrity(exit_code: int, output: str) -> VerificationCheck:
    """restic check — is the archive internally consistent."""
    ok = exit_code == 0
    return VerificationCheck(
        name="repository_integrity",
        passed=ok,
        detail=(
            "restic check passed (metadata consistent)"
            if ok else _first_error(output, "restic check reported problems")
        ),
    )


def snapshot_exists(snapshots: List[dict], host: str = "") -> VerificationCheck:
    """Does the repository actually hold anything for this machine.

    An empty repository is the most dangerous state in backup: the job
    reports success every night because it has nothing to fail on.
    """
    count = len(snapshots or [])
    if count:
        return VerificationCheck(
            "snapshot_exists", True, f"{count} snapshot(s) present"
        )
    where = f" for host {host}" if host else ""
    return VerificationCheck(
        "snapshot_exists", False,
        f"the repository holds no snapshots{where} — nothing to restore",
    )


def data_recency(
    snapshot_time: Optional[str],
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: Optional[datetime] = None,
) -> VerificationCheck:
    """How old the newest snapshot is."""
    if not snapshot_time:
        return VerificationCheck(
            "data_recency", False, "snapshot carries no timestamp"
        )

    parsed = _parse_time(snapshot_time)
    if parsed is None:
        return VerificationCheck(
            "data_recency", False, f"unreadable snapshot time: {snapshot_time}"
        )

    reference = now or datetime.now(timezone.utc)
    age = reference - parsed
    fresh = age <= timedelta(days=max_age_days)
    return VerificationCheck(
        "data_recency", fresh,
        f"newest snapshot is {age.days} day(s) old "
        f"(threshold {max_age_days})",
    )


def file_restore(exit_code: int, restored_bytes: int, output: str) -> VerificationCheck:
    """Did data actually come back out of the archive.

    Zero bytes with a zero exit code is treated as a failure. restic can
    exit cleanly having restored an empty selection, and a check that
    accepted that would pass on a backup containing nothing — the exact
    error this module exists to catch.
    """
    if exit_code != 0:
        return VerificationCheck(
            "file_restore", False, _first_error(output, "restore failed")
        )
    if restored_bytes <= 0:
        return VerificationCheck(
            "file_restore", False,
            "restore exited cleanly but wrote no data",
        )
    return VerificationCheck(
        "file_restore", True, f"{restored_bytes:,} bytes restored"
    )


def guest_boot(booted: bool, detail: str) -> VerificationCheck:
    """Did the restored image reach a running state."""
    return VerificationCheck(
        "guest_boot", booted,
        detail or ("guest reached running state" if booted else "guest did not boot"),
    )


def guest_stayed_up(still_running: bool, seconds: int) -> VerificationCheck:
    """Is it still running a while later, or did it boot-loop.

    A machine that reaches "running" and dies four seconds later has not
    recovered, and the instant of reaching running is exactly when a
    naive check would declare success. Restored systems fail this way
    often — a missing driver panics after the kernel loads, not before.
    """
    return VerificationCheck(
        "guest_stayed_up", still_running,
        f"still running after {seconds}s" if still_running
        else f"stopped within {seconds}s of starting — boot loop or panic",
    )


def _nothing_recognisable(console) -> VerificationCheck:
    """A console we could read that told us nothing we understand.

    "Empty" and "unrecognised" are different facts with different fixes,
    and the first real Hyper-V run could not tell them apart because
    both arrived as the same sentence.

    - **Empty**: the reader connected, the guest never wrote to its
      serial port. That is a fact about the guest's configuration, not
      about the backup.
    - **Unrecognised**: the guest spoke and our phrase list is too
      narrow. That is a fact about this file.

    The same distinction the threat feeds already draw between absent,
    unreadable and empty — and for the same reason. Neither outcome
    passes; both are "could not confirm".
    """
    text = (console.text or "").strip()
    if not text:
        return VerificationCheck(
            "guest_console", False,
            "console capture is EMPTY — the reader connected but the "
            "guest never wrote to its serial port. Not evidence about "
            "the backup; evidence the guest has no serial console.",
        )
    lines = text.splitlines()
    sample = " / ".join(lines[:3])[:160]
    return VerificationCheck(
        "guest_console", False,
        f"console had {len(lines)} line(s) but no recognisable boot "
        f"progress — 'could not confirm', not 'confirmed healthy'. "
        f"First lines: {sample}",
    )


def guest_console(console) -> VerificationCheck:
    """What the guest said on its serial console, read from the host.

    Three outcomes, kept apart:

    - a known failure string (`kernel panic`, `no bootable device`) —
      **fails**, and names what it saw
    - recognisable life signs — passes
    - console readable but unrecognised, or not readable at all —
      **fails as "could not check"**, never passes

    That last one is the rule this platform runs on. A console we could
    not read has told us nothing about the guest, and nothing is not
    health. It is reported as a failure rather than a skip because the
    caller asked for a boot test and did not get one.
    """
    if not console.available:
        return VerificationCheck(
            "guest_console", False,
            f"could not read the guest console: {console.reason}",
        )
    failures = console.failures
    if failures:
        return VerificationCheck(
            "guest_console", False,
            f"console reports boot failure: {', '.join(failures)}",
        )
    signs = console.life_signs
    if not signs:
        return _nothing_recognisable(console)
    return VerificationCheck(
        "guest_console", True, f"console shows boot progress: {', '.join(signs)}"
    )


def _parse_time(value: str) -> Optional[datetime]:
    """Parse restic's RFC3339 timestamps, including nanosecond precision."""
    text = value.strip().replace("Z", "+00:00")
    # restic emits nanoseconds; fromisoformat accepts at most microseconds.
    if "." in text:
        head, _, tail = text.partition(".")
        digits = "".join(c for c in tail if c.isdigit())[:6]
        offset = tail[len(digits):].lstrip("0123456789")
        text = f"{head}.{digits}{offset}" if digits else head + offset
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _first_error(output: str, fallback: str, lines: int = 3) -> str:
    """The first few meaningful lines of tool output, as one line.

    One line was not enough. The first live corruption run reported
    `error for tree 8b91b591:` and stopped — a message that names the
    problem's location and nothing about the problem. restic puts the
    useful half on the following lines, so a few are joined.
    """
    meaningful = [ln.strip() for ln in (output or "").splitlines() if ln.strip()]
    if not meaningful:
        return fallback
    return "; ".join(meaningful[:lines])[:300]
