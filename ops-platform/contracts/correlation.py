"""Cross-signal correlation — pure data.

A `Correlation` says: *these separate findings are one story.* It is the
platform's central claim, and therefore the single easiest place to
start lying.

The failure mode is specific and worth naming. A correlation engine that
combines two soft signals into one loud alarm — "possible compromise!" —
produces exactly the tool a solo admin stops trusting after the third
false alarm. netdiag's own field campaign found nineteen of twenty bugs
were the tool being *confidently wrong*, and every fix made a claim
narrower rather than louder. This contract encodes that lesson as rules
that cannot be forgotten:

**1. Confidence can never exceed the weakest member.** Two `likely`
findings do not make a `certain` conclusion. Correlation adds *meaning*,
not evidence — the same facts are being read together, and reading them
together does not make them more measured than they were.

**2. Severity can never exceed the strongest member.** Two warnings must
not be alchemised into a critical. If a story genuinely warrants
escalation, one of its parts was already that serious.

**3. Coverage travels, and it is the *worst* of the members.** A story
assembled from a machine where half the checks were skipped is a story
with a hole in it, and it says so.
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import List, Optional

from contracts.citation import GROUNDED, NOT_REQUESTED, Citation
from contracts.finding import CONFIDENCES, SEVERITIES, Coverage, Finding

CONTRACT_VERSION = "0.1.0"

# Lower index = stronger claim, matching the tuples in finding.py.
_CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCES)}
_SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Correlation:
    """Several findings that are better understood as one thing."""

    id: str
    machine_id: str
    story: str
    members: List[Finding]
    severity: str
    confidence: str
    suggested_action: Optional[str] = None

    # A correlation that tells you what NOT to chase is as valuable as
    # one that raises an alarm. `suppresses` names member findings whose
    # separate alerts this story explains away — e.g. DNS failing because
    # a captive portal is intercepting, which is not a DNS fault.
    suppresses: tuple = ()

    # What this story stands on. Retrieved from the knowledge base when
    # the correlation fires; `grounding` records why the list is empty
    # when it is, because "we did not look" and "we looked and found
    # nothing" send a reader to different places.
    citations: tuple = ()
    grounding: str = NOT_REQUESTED

    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self):
        if len(self.members) < 2:
            raise ValueError(
                "a correlation needs at least two findings; one finding is "
                "just a finding"
            )
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"invalid confidence: {self.confidence!r}")
        if not self.story:
            raise ValueError("a correlation must state its story")

        self._enforce_no_manufactured_certainty()
        self._enforce_no_manufactured_severity()
        if isinstance(self.suppresses, list):
            self.suppresses = tuple(self.suppresses)
        if isinstance(self.citations, list):
            self.citations = tuple(self.citations)
        if self.citations and self.grounding != GROUNDED:
            raise ValueError(
                "a correlation carrying citations must be marked grounded; "
                "otherwise the report and the record disagree"
            )

    def _enforce_no_manufactured_certainty(self):
        weakest = max(_CONFIDENCE_RANK[m.confidence] for m in self.members)
        if _CONFIDENCE_RANK[self.confidence] < weakest:
            raise ValueError(
                f"correlation claims {self.confidence!r} but its weakest "
                f"member is {CONFIDENCES[weakest]!r}; reading findings "
                f"together does not make them better measured"
            )

    def _enforce_no_manufactured_severity(self):
        strongest = min(_SEVERITY_RANK[m.severity] for m in self.members)
        if _SEVERITY_RANK[self.severity] < strongest:
            raise ValueError(
                f"correlation claims {self.severity!r} but its most severe "
                f"member is {SEVERITIES[strongest]!r}; correlation adds "
                f"meaning, not urgency"
            )

    @property
    def coverage(self) -> Coverage:
        """The worst coverage among members.

        A story is only as complete as its least-examined part.
        """
        return min(
            (m.coverage for m in self.members),
            key=lambda c: (c.checked / c.total) if c.total else 0.0,
        )

    @property
    def member_ids(self) -> tuple:
        return tuple(m.id for m in self.members)

    @property
    def sources(self) -> tuple:
        """Which engines contributed. Two sources is a cross-signal story."""
        return tuple(sorted({m.source_module for m in self.members}))

    @property
    def is_cross_source(self) -> bool:
        """Whether this spans engines rather than restating one engine.

        The platform's distinguishing claim is specifically about stories
        that no single tool could tell.
        """
        return len(self.sources) > 1

    @property
    def involves_security(self) -> bool:
        return any(m.is_security for m in self.members)

    @property
    def is_grounded(self) -> bool:
        """Whether this story can show what it stands on.

        A story is not wrong for being ungrounded — the authored text is
        reviewed and deterministic. But a reader deserves to know which
        kind they are looking at, and a report that renders both
        identically has quietly turned "no supporting entry was found"
        into silence.
        """
        return self.grounding == GROUNDED and bool(self.citations)

    @property
    def techniques(self) -> tuple:
        """ATT&CK technique ids cited, in citation order."""
        return tuple(
            c.technique for c in self.citations if getattr(c, "technique", None)
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["coverage"] = asdict(self.coverage)
        data["sources"] = list(self.sources)
        data["citations"] = [c.to_dict() for c in self.citations]
        return data
