"""Correlation domain service — the cross-signal engine.

**Why this is a domain and not an agent.** The architecture forbids
domains importing each other, and correlation clearly spans them. But it
does not import `domains.diagnostics` or `domains.network` — it takes
`Finding` contracts as input. That is precisely what the contract layer
is for: correlation depends on the shared *language*, not on the
subdomains that happen to speak it. It would work unchanged against a
third engine nobody has written yet.

Putting it in the agent layer would have made it business logic inside a
router, which is how agents turn into god-files.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from contracts import Correlation, Finding
from contracts.citation import GROUNDED, NO_KB, NO_MATCH
from contracts.finding import CONFIDENCES, SEVERITIES
from domains.correlation import rules as rules_module


def _strongest_first(correlations: List[Correlation]) -> List[Correlation]:
    """Order stories so the one to act on leads.

    More than one rule can legitimately explain the same finding — a dead
    link and a captive portal both explain a DNS failure. Presenting them
    in rule-declaration order would make the lead story an accident of
    file layout, so they are ranked by severity, then confidence, then
    by how much they explain.
    """
    severity_rank = {s: i for i, s in enumerate(SEVERITIES)}
    confidence_rank = {c: i for i, c in enumerate(CONFIDENCES)}
    return sorted(
        correlations,
        key=lambda c: (
            severity_rank.get(c.severity, 99),
            confidence_rank.get(c.confidence, 99),
            -len(c.members),
        ),
    )


@dataclass
class TriageResult:
    """Findings after correlation: what is one story, and what to ignore."""

    correlations: List[Correlation] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    suppressed_ids: tuple = ()
    sources_present: tuple = ()
    machine_id: str = "unknown"
    grounding_available: bool = False

    @property
    def standalone_findings(self) -> List[Finding]:
        """Findings not explained by any correlation.

        Suppressed findings are removed from the headline list but never
        deleted — they remain in `findings` and inside the correlation
        that explains them. Silently dropping a symptom would leave a
        reader unable to check the reasoning.
        """
        explained = {
            m.id for c in self.correlations for m in c.members
        } | set(self.suppressed_ids)
        return [f for f in self.findings if f.id not in explained]

    @property
    def cross_source(self) -> List[Correlation]:
        """Stories no single engine could have told."""
        return [c for c in self.correlations if c.is_cross_source]

    @property
    def security_correlations(self) -> List[Correlation]:
        return [c for c in self.correlations if c.involves_security]

    @property
    def ungrounded(self) -> List[Correlation]:
        """Stories with no supporting knowledge-base entry.

        Reported rather than filtered. The story is still the best
        available reading of the findings; what a reader loses without
        this list is the ability to tell which conclusions they can
        check and which they must take on trust.
        """
        return [c for c in self.correlations if not c.is_grounded]

    @property
    def is_single_source(self) -> bool:
        """Whether only one engine contributed.

        Surfaced because it bounds what correlation could possibly have
        found: with one engine's findings, cross-signal stories cannot be
        detected, and reporting "no correlations" without that caveat
        would imply an all-clear that was never tested for.
        """
        return len(self.sources_present) < 2


class CorrelationService:
    """Reads findings from any number of engines; reports shared stories."""

    def __init__(self, rules=None, knowledge=None):
        self.rules = rules if rules is not None else rules_module.RULES
        # Optional on purpose. Correlation must keep working with no
        # knowledge base — the stories are authored and deterministic,
        # and grounding adds references to them rather than producing
        # them. What must never happen is an ungrounded story being
        # rendered as though it were sourced, which is why the reason
        # travels with the result instead of being inferred from an
        # empty list.
        self.knowledge = knowledge

    def correlate(
        self,
        findings: List[Finding],
        machine_id: Optional[str] = None,
    ) -> TriageResult:
        """Group findings into stories.

        Findings from different machines are not correlated: two machines
        failing DNS is a fleet observation, not one machine's story, and
        conflating them would invent causation across hosts.
        """
        if not findings:
            return TriageResult(machine_id=machine_id or "unknown")

        machine = machine_id or findings[0].machine_id
        scoped = [f for f in findings if f.machine_id == machine]
        by_id: Dict[str, Finding] = {f.id: f for f in scoped}

        correlations, suppressed = [], set()
        for rule in self.rules:
            if not rule.matches(by_id):
                continue
            citations, grounding = self._ground(rule)
            correlations.append(rule.build(by_id, machine, citations, grounding))
            suppressed.update(rule.suppresses)

        return TriageResult(
            grounding_available=bool(
                self.knowledge and self.knowledge.is_available
            ),
            correlations=_strongest_first(correlations),
            findings=scoped,
            suppressed_ids=tuple(sorted(suppressed)),
            sources_present=tuple(sorted({f.source_module for f in scoped})),
            machine_id=machine,
        )

    def _ground(self, rule):
        """Find knowledge-base support for a rule, or say why there is none.

        Exact keying first, similarity search only as a fallback. A rule
        whose supporting entry someone deliberately wrote should get that
        entry rather than whatever scored highest — retrieval is for the
        cases nobody anticipated, not a replacement for the ones somebody
        did.
        """
        if self.knowledge is None:
            return (), NO_KB
        if not self.knowledge.is_available:
            reason = self.knowledge.unavailable_reason
            return (), f"{NO_KB} ({reason})" if reason else NO_KB

        citations = self.knowledge.for_topic(rule.id)
        if not citations:
            citations = self.knowledge.search(rule.kb_query, top_k=2)
        if not citations:
            return (), NO_MATCH
        return tuple(citations), GROUNDED
