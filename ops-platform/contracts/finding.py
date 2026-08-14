"""Shared finding schema — the one data shape every module speaks.

Milestone 0 of the implementation plan. Diagnostics (Diagnostic
Companion), network diagnostics (netdiag), backup verification and the
AI triage layer all produce or consume `Finding` records in this shape.

Two deliberate choices, both inherited rather than invented:

**The vocabulary is Diagnostic Companion's, not a new one.** Severity is
`critical`/`warning`/`info` and confidence is `certain`/`likely`/
`possible`, matching `interpreter.py` exactly. Inventing a parallel
vocabulary here would mean writing a translation layer on day one and
maintaining two sets of semantics forever. netdiag's findings get
mapped onto these terms by its adapter, which is the adapter's job.

**Coverage travels with every finding.** Both source tools already
enforce "absence is never health" — a check that could not run is
reported, never omitted. A `Finding` therefore carries `checked` and
`total` so a score or a summary built from these records can never
quietly present partial data as complete. Dropping coverage at this
boundary would discard the single most important property of both
upstream tools.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Optional

SCHEMA_VERSION = "0.1.0"

SEVERITIES = ("critical", "warning", "info")
CONFIDENCES = ("certain", "likely", "possible")

# Modules permitted to emit findings. Kept as a closed set so a typo in
# a source name surfaces immediately rather than silently creating a
# phantom source that the console then renders as its own section.
SOURCE_MODULES = (
    "diagnostic-companion",
    "netdiag",
    "backup-verify",
    "lan-census",
    "lan-anomaly",
    "lan-exposure",
    "lan-poison",
    "manual",
)


@dataclass
class Coverage:
    """How much of what was meant to be checked actually got checked."""

    checked: int
    total: int

    def __post_init__(self):
        if self.checked < 0 or self.total < 0:
            raise ValueError("coverage counts cannot be negative")
        if self.checked > self.total:
            raise ValueError(
                f"checked ({self.checked}) exceeds total ({self.total})"
            )

    @property
    def is_complete(self) -> bool:
        return self.checked == self.total

    def __str__(self) -> str:
        return f"{self.checked}/{self.total} checked"


@dataclass
class Finding:
    """One thing observed about one machine, by one module."""

    id: str
    source_module: str
    machine_id: str
    severity: str
    confidence: str
    message: str
    coverage: Coverage
    suggested_action: Optional[str] = None

    # Jargon-free rendering of the same finding, where the source tool
    # provides one. netdiag ships `for_user` text written for someone who
    # does not know what a gateway is; discarding it would throw away the
    # best plain-language asset either engine has. None means the source
    # offered no plain version — never a silently reworded technical one.
    plain_message: Optional[str] = None

    # Free-form classification, e.g. ("security",) or ("layer:L7",).
    # Exists so cross-domain correlation has something to match on: a
    # security-tagged network finding and a diagnostic finding about the
    # same machine are what "one story, not two blips" is built from.
    tags: tuple = ()

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self):
        if self.source_module not in SOURCE_MODULES:
            raise ValueError(
                f"unknown source_module: {self.source_module!r} "
                f"(expected one of {SOURCE_MODULES})"
            )
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"invalid severity: {self.severity!r} "
                f"(expected one of {SEVERITIES})"
            )
        if self.confidence not in CONFIDENCES:
            raise ValueError(
                f"invalid confidence: {self.confidence!r} "
                f"(expected one of {CONFIDENCES})"
            )
        if not self.message:
            raise ValueError("a finding must carry a message")
        if isinstance(self.coverage, dict):
            self.coverage = Coverage(**self.coverage)
        if isinstance(self.tags, list):
            self.tags = tuple(self.tags)

    @property
    def is_security(self) -> bool:
        """Whether this finding concerns security posture rather than health."""
        return "security" in self.tags

    def for_display(self) -> str:
        """Plain text if the source provided it, otherwise the technical text.

        Falls back rather than inventing: a reworded technical message is
        not the same thing as text an engineer wrote for a non-engineer.
        """
        return self.plain_message or self.message

    @property
    def can_headline(self) -> bool:
        """Whether this finding may lead a report.

        Mirrors Diagnostic Companion's rule (spec §3.5): a `possible`
        finding is never allowed to headline, because presenting a
        maybe as the top-line conclusion is how a diagnostic tool
        trains people to distrust it.
        """
        return self.confidence != "possible"

    @property
    def is_actionable(self) -> bool:
        """Only `certain` criticals justify an alarm.

        Same rule Diagnostic Companion uses to decide its exit code:
        confidence gates escalation, so a `likely` critical informs but
        does not cry wolf.
        """
        return self.severity == "critical" and self.confidence == "certain"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        data = dict(data)
        data.pop("schema_version", None)
        return cls(**data)


def sort_findings(findings):
    """Order findings the way a reader needs them: worst and most
    certain first. Matches `interpreter.py`'s severity ordering, with
    confidence as the tiebreaker so a certain warning outranks a
    possible one."""
    severity_rank = {s: i for i, s in enumerate(SEVERITIES)}
    confidence_rank = {c: i for i, c in enumerate(CONFIDENCES)}
    return sorted(
        findings,
        key=lambda f: (
            severity_rank.get(f.severity, 99),
            confidence_rank.get(f.confidence, 99),
        ),
    )
