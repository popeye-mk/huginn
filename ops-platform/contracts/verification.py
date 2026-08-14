"""Backup restore verification results — pure data.

The design doc's sharpest statistic drives this contract: 82% of backup
jobs have restore-testing set to "never", and 31% of organisations fail
to recover despite 92% believing they have backups. The gap is not
between backed-up and not-backed-up; it is between *believed* and
*proven*.

So this contract refuses to represent a belief. A verification is
`PASSED` only when a restore was actually performed and checked. There
is deliberately no "probably fine" state — that state is what the
industry already has, and it is the problem.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

CONTRACT_VERSION = "0.1.0"


class VerificationStatus(Enum):
    """Outcome of a restore verification attempt.

    `NOT_ATTEMPTED` is a first-class value, not an absence. A device
    with no verification must render differently from one that passed —
    silence is the failure mode this whole module exists to eliminate.
    """

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"              # the check itself broke; says nothing about the backup
    NOT_ATTEMPTED = "not_attempted"


class VerificationDepth(Enum):
    """How far the verification actually went.

    The distinction this platform exists to make. A repository integrity
    check proves the archive is not corrupt. A file restore proves bytes
    come back out. **Neither proves the machine boots** — and "we restored
    some files successfully" is exactly the reassurance that lets an
    organisation discover on the bad day that its domain controller will
    not come up.

    So depth is a field, not a footnote, and `is_proof_of_recovery`
    requires `BOOT`. Anything shallower is real evidence of something
    real, labelled as what it is.
    """

    REPOSITORY = "repository"    # integrity check only; no data left the archive
    FILE = "file"                # data restored and verified on disk
    BOOT = "boot"                # restored, booted, and checked from inside


@dataclass
class VerificationCheck:
    """One check performed against a restored system."""

    name: str                    # "boot" | "services" | "data_recency" | "checksum"
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RestoreVerification:
    """The result of restoring a backup and checking it.

    Evidence for the "proof of recovery" that cyber-insurance
    underwriters increasingly ask for — which only holds if the record
    is honest about partial runs.
    """

    device_id: str
    status: VerificationStatus
    depth: VerificationDepth = VerificationDepth.REPOSITORY
    repository: str = ""
    snapshot_id: str = ""
    checks: List[VerificationCheck] = field(default_factory=list)
    # Why the verification did not go deeper — "no hypervisor on this
    # host", "no guest credentials". Carried alongside the result so a
    # shallow pass always arrives with its own caveat attached, rather
    # than needing the reader to know what to ask.
    depth_limited_by: str = ""
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: Optional[float] = None
    error_message: str = ""
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self):
        if not self.device_id:
            raise ValueError("device_id is required")
        if isinstance(self.status, str):
            self.status = VerificationStatus(self.status)
        if isinstance(self.depth, str):
            self.depth = VerificationDepth(self.depth)

        # A pass must be evidenced. Allowing PASSED with no checks would
        # let an empty run masquerade as proof of recovery, which is the
        # precise false confidence this contract exists to prevent.
        if self.status is VerificationStatus.PASSED and not self.checks:
            raise ValueError(
                "a PASSED verification must carry the checks that passed"
            )
        if self.status is VerificationStatus.PASSED and not all(
            c.passed for c in self.checks
        ):
            raise ValueError(
                "PASSED contradicts a failing check; use FAILED"
            )

    @property
    def is_proof_of_recovery(self) -> bool:
        """Whether this record can be shown as evidence recovery works.

        Requires `BOOT`. An underwriter asking for proof of recovery is
        asking whether the business comes back, and a successful file
        restore does not answer that question. Returning True for a
        shallower run would make this property the very thing it was
        written to replace.
        """
        return (
            self.status is VerificationStatus.PASSED
            and self.depth is VerificationDepth.BOOT
            and bool(self.checks)
        )

    @property
    def failed_checks(self) -> List[VerificationCheck]:
        return [c for c in self.checks if not c.passed]

    @property
    def summary(self) -> str:
        """One line an admin can read without decoding the fields."""
        if self.status is VerificationStatus.NOT_ATTEMPTED:
            return f"not verified — {self.error_message or 'no attempt made'}"
        if self.status is VerificationStatus.ERROR:
            return f"verification broke — {self.error_message} (backup unproven)"
        if self.status is VerificationStatus.FAILED:
            names = ", ".join(c.name for c in self.failed_checks) or "unknown"
            return f"restore FAILED at: {names}"
        if self.is_proof_of_recovery:
            return f"restored and booted — {len(self.checks)} check(s) passed"
        return (
            f"{self.depth.value}-level restore passed "
            f"({len(self.checks)} check(s)) — not a boot test"
            + (f"; {self.depth_limited_by}" if self.depth_limited_by else "")
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["depth"] = self.depth.value
        return data
