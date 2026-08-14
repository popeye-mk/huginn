"""Network domain service — the public entry point.

Mirrors the diagnostics service deliberately: same shape, same split
between `service` and `mapping`, same rule that callers import only this
module. Two subdomains that behave the same way are two subdomains
someone can learn once.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from contracts import Finding
from domains.network import mapping
from engines.netdiag import NetdiagEngine


@dataclass
class NetworkResult:
    """Findings plus netdiag's blame partition.

    The blame verdict is carried alongside rather than flattened into a
    finding, for the same reason Diagnostic Companion's chains are:
    "the problem is past your gateway, not your machine" is a statement
    *about* the findings. It is also the single most useful sentence
    netdiag produces — it is what turns a wall of facts into a decision —
    so losing it in a list of findings would discard the tool's headline
    feature.
    """

    findings: List[Finding] = field(default_factory=list)
    blame: Dict[str, Any] = field(default_factory=dict)
    snapshot: Dict[str, Any] = field(default_factory=dict)
    not_checked: List[tuple] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def machine_id(self) -> str:
        return self.snapshot.get("hostname", "unknown")

    @property
    def verdict(self) -> str:
        """netdiag's blame partition, in one sentence."""
        return self.blame.get("verdict", "")

    @property
    def security_findings(self) -> List[Finding]:
        """Exposure findings, as distinct from connectivity problems."""
        return [f for f in self.findings if f.is_security]

    @property
    def actionable(self) -> List[Finding]:
        return [f for f in self.findings if f.is_actionable]

    @property
    def unknown_segments(self) -> List[str]:
        """Segments netdiag could not grade.

        Surfaced rather than buried: a segment whose probe was skipped is
        `unknown`, never silently green, and a caller summarising the
        blame verdict needs to be able to say so.
        """
        return [
            s.get("name", "?")
            for s in self.blame.get("segments") or []
            if s.get("status") == "unknown"
        ]

    @property
    def has_gaps(self) -> bool:
        return bool(self.not_checked) or bool(self.unknown_segments)


class NetworkService:
    """Network-layer diagnostics and security posture."""

    def __init__(self, engine: Optional[NetdiagEngine] = None):
        self.engine = engine or NetdiagEngine()

    def is_available(self) -> bool:
        return self.engine.is_available()

    def run(self, machine_id: Optional[str] = None) -> NetworkResult:
        """Passive network scan: findings, blame partition, hygiene posture."""
        output = self.engine.run()
        return self._build(output.payload or {}, machine_id)

    def why(
        self,
        symptom: str,
        target: str = "",
        machine_id: Optional[str] = None,
    ) -> NetworkResult:
        """Symptom-driven layer walk — netdiag's `why` verb.

        Exposed because it matches how tickets actually arrive: users say
        "I can't log in", not "check my SRV records".
        """
        output = self.engine.why(symptom, target=target)
        return self._build(output.payload or {}, machine_id)

    def _build(self, payload: dict, machine_id: Optional[str]) -> NetworkResult:
        return NetworkResult(
            findings=mapping.to_findings(payload, machine_id=machine_id),
            blame=payload.get("blame") or {},
            snapshot=payload.get("snapshot") or {},
            not_checked=mapping.extract_not_checked(payload),
            raw=payload,
        )
