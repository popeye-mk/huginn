"""`backup` skill — can this machine actually be restored?

The output is written to be readable by someone who is not thinking
clearly, because the person asking this question is often mid-incident.
So the verdict is the first line, the depth of the test is stated
immediately after it, and every check is listed with what it proved.

**The formatting rule this skill exists to enforce:** never print a bare
"backup OK". A file-level restore and a booted restore are different
claims, and a line that does not say which one happened is the reassuring
half-truth this whole domain was built to eliminate.
"""

from typing import Any

from agents.instance import get_agent
from contracts import VerificationDepth, VerificationStatus

_STATUS_LINE = {
    VerificationStatus.PASSED: "  RESTORE VERIFIED",
    VerificationStatus.FAILED: "  RESTORE FAILED",
    VerificationStatus.ERROR: "  VERIFICATION BROKE — the backup is unproven",
    VerificationStatus.NOT_ATTEMPTED: "  NOT VERIFIED",
}

_DEPTH_LINE = {
    VerificationDepth.REPOSITORY: (
        "Repository integrity only — no data was restored."
    ),
    VerificationDepth.FILE: (
        "File-level restore — data came back out. The machine was NOT booted."
    ),
    VerificationDepth.BOOT: (
        "Full restore — the machine was rebuilt, booted and checked from inside."
    ),
}


def _render_checks(verification) -> list:
    if not verification.checks:
        return []
    lines = ["", "  Checks", "  " + "-" * 58]
    for check in verification.checks:
        mark = "pass" if check.passed else "FAIL"
        lines.append(f"   [{mark}] {check.name:22} {check.detail}")
    return lines


def _render_history(previous) -> list:
    """Past attempts. Absence of history is itself the headline."""
    if len(previous) <= 1:
        return [
            "", "  No earlier verification on record. A backup verified once "
            "is not a backup you can rely on — schedule this."
        ]
    lines = ["", "  Earlier attempts", "  " + "-" * 58]
    for record in previous[1:5]:
        lines.append(
            f"   {record.started_at[:19]}  {record.status.value:14} "
            f"{record.depth.value}"
        )
    return lines


def skill_backup(args: str, speaker: Any = None) -> str:
    """Verify a backup and report exactly how far the test got."""
    del speaker
    boot_test = "boot" in (args or "").lower()

    result = get_agent().backup_check(boot_test=boot_test)
    if not result.get("ok"):
        return str(result.get("body") or "Backup verification did not run.")

    verification = result["verification"]
    lines = [_STATUS_LINE[verification.status], "  " + "=" * 58]

    if verification.status is VerificationStatus.NOT_ATTEMPTED:
        lines.append(f"  {verification.error_message}")
        lines.append("")
        lines.append(
            "  Nothing here says your backups are bad. It says nobody has "
            "checked — which is the state 82% of backup jobs are in."
        )
        return "\n".join(lines)

    lines.append(f"  {_DEPTH_LINE[verification.depth]}")
    if verification.depth_limited_by:
        lines.append(f"  Limited by: {verification.depth_limited_by}")
    if verification.error_message:
        lines.append(f"  {verification.error_message}")

    lines += _render_checks(verification)
    lines += _render_history(result.get("previous") or [])

    lines += ["", "  " + "-" * 58, f"  {verification.summary}"]
    if not verification.is_proof_of_recovery:
        lines.append(
            "  This is not yet proof of recovery — that needs a boot test."
        )
    if result.get("record_error"):
        lines.append(f"  (result not saved: {result['record_error']})")
    return "\n".join(lines)


def register(registry) -> None:
    """Registered natively as of 2026-07-27.

    This verb had a skill function and no `register()`, so the native
    shell's `auto_discover` never saw it. It had been reached through the
    vendored fork's router; when the fork was archived on 2026-07-26 the
    verb stopped existing — silently, because discovery swallowed the
    absence. The console kept a Backup button that answered "not an ops
    verb". Registration is what makes a verb real here.
    """
    registry.register(
        "backup",
        skill_backup,
        aliases=[
            "backup check", "can we restore", "restore test", "restic",
            "verify backup", "backup verification",
            "back-up", "kunnen we herstellen",             # NL
            "sauvegarde", "pouvons-nous restaurer",        # FR
        ],
    )
