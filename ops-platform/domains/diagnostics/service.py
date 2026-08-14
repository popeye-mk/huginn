"""Diagnostics domain service — the public entry point.

Layers above import this and nothing else from the domain. Engine
handling and mapping stay internal, so swapping Diagnostic Companion for
another host-health tool would change `engine` and `mapping` while
leaving every caller untouched.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from contracts import Finding
from domains.diagnostics import mapping
from engines.diagnostic_companion import DiagnosticCompanionEngine


@dataclass
class DiagnosticsResult:
    """Findings plus the context that explains them.

    Chains, verdict and score are carried alongside rather than folded
    into `Finding` records: they are statements *about* the set of
    findings, not findings themselves. Flattening them would discard the
    causal grouping that is Diagnostic Companion's main contribution —
    "the disk is full, which is why the logs are full of errors" is worth
    more than the two findings separately.
    """

    findings: List[Finding] = field(default_factory=list)
    chains: List[dict] = field(default_factory=list)
    verdict: Dict[str, Any] = field(default_factory=dict)
    health_score: Dict[str, Any] = field(default_factory=dict)
    snapshot: Dict[str, Any] = field(default_factory=dict)
    not_checked: List[tuple] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def machine_id(self) -> str:
        return self.snapshot.get("hostname", "unknown")

    @property
    def actionable(self) -> List[Finding]:
        """Findings that justify acting now: certain criticals only."""
        return [f for f in self.findings if f.is_actionable]

    @property
    def headline(self) -> str:
        return self.verdict.get("headline", "")

    @property
    def has_gaps(self) -> bool:
        """Whether anything could not be checked.

        Exposed so callers can avoid presenting a partial run as a clean
        bill of health.
        """
        return bool(self.not_checked)


class DiagnosticsService:
    """Host health diagnostics."""

    def __init__(self, engine: Optional[DiagnosticCompanionEngine] = None):
        self.engine = engine or DiagnosticCompanionEngine()

    def is_available(self) -> bool:
        return self.engine.is_available()

    def run(
        self,
        demo: Optional[str] = None,
        machine_id: Optional[str] = None,
    ) -> DiagnosticsResult:
        """Collect diagnostics and return mapped findings with context."""
        output = self.engine.run(demo=demo)
        payload = output.payload or {}

        return DiagnosticsResult(
            findings=mapping.to_findings(payload, machine_id=machine_id),
            chains=payload.get("chains") or [],
            verdict=payload.get("verdict") or {},
            health_score=payload.get("health_score") or {},
            snapshot=payload.get("snapshot") or {},
            not_checked=mapping.extract_not_checked(payload),
            raw=payload,
        )
