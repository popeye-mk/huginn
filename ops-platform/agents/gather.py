"""Collect findings from whichever engines are available.

Split out of `ops_agent` when its triage handler outgrew the 50-line
function limit. That limit did its job: gathering-from-many-engines and
routing-a-request are two responsibilities, and they were only sharing a
function because both happened to be needed at the same moment.

The important behaviour here is what happens when an engine is *missing*.
It is recorded, not skipped silently. A correlation report built from one
engine has not tested for cross-signal stories at all, and the caller
needs to be able to say so rather than implying an all-clear.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

from contracts import Finding


@dataclass
class Gathered:
    """Findings from every engine that ran, plus what did not run."""

    findings: List[Finding] = field(default_factory=list)
    not_checked: List[tuple] = field(default_factory=list)
    engines_run: Tuple[str, ...] = ()
    engines_missing: Tuple[str, ...] = ()

    # Carried for the fleet view. The diagnostics snapshot is what
    # `fleet.py` correlates over, and re-running the engine to obtain it
    # would double the cost of every triage.
    snapshot: dict = field(default_factory=dict)
    health_score: dict = field(default_factory=dict)

    # What the threat check managed to compare. Carried so triage can
    # say "0/12 checked" rather than implying an all-clear it never
    # earned — the same rule the engines follow, applied to feeds.
    threat_summary: str = ""

    @property
    def machine_id(self) -> str:
        return self.findings[0].machine_id if self.findings else "unknown"

    @property
    def any_engine_ran(self) -> bool:
        return bool(self.engines_run)


def _normalise_machine_id(findings: List[Finding], machine: str) -> None:
    """Give every finding the same machine identity.

    Engines can report the same box differently — one may use the short
    hostname, another the FQDN. Correlation is scoped to a single machine,
    so without this the two engines' findings would never match and
    cross-signal stories would silently never fire. Normalising here is
    visible; a silent non-match would not be.
    """
    for finding in findings:
        finding.machine_id = machine


def _run_engines(diagnostics, network):
    """Run each available engine, recording what did not run.

    Extracted when `collect` crossed the 50-line limit. The split is
    along a real seam: this knows about engines, `collect` knows about
    assembling a result, and only one of them changes when a fourth
    engine appears.
    """
    findings: List[Finding] = []
    not_checked: List[tuple] = []
    ran: List[str] = []
    missing: List[str] = []
    snapshot: dict = {}
    health_score: dict = {}

    for name, service, runner in (
        ("diagnostic-companion", diagnostics, lambda s: s.run()),
        ("netdiag", network, lambda s: s.run()),
    ):
        if not service.is_available():
            missing.append(name)
            continue
        result = runner(service)
        findings += result.findings
        not_checked += result.not_checked
        ran.append(name)

        # Only Diagnostic Companion's snapshot shape is what fleet.py
        # correlates over; netdiag's is a different schema.
        if name == "diagnostic-companion":
            snapshot = getattr(result, "snapshot", {}) or {}
            health_score = getattr(result, "health_score", {}) or {}

    return findings, not_checked, ran, missing, snapshot, health_score


def _threat_findings(threat, connections):
    """Check observed connections against threat feeds.

    Returns `(findings, summary, checked_anything)`. Failure is caught
    and reported rather than raised: a feed problem must not cost the
    user their diagnostics, and `checked_anything` is what stops an
    unusable feed from being mistaken for a clean result.
    """
    try:
        observed = connections()
    except Exception as exc:  # noqa: BLE001
        return [], f"connections could not be listed: {exc}", False

    result = threat.match(observed)
    return result.findings, result.summary, result.checked_anything


def collect(diagnostics, network, threat=None, connections=None) -> Gathered:
    """Run each available service and merge the results.

    `threat` and `connections` are optional so every existing caller and
    test keeps working unchanged. When both are supplied, outbound
    connections are checked against threat feeds and the matches join
    the same finding list — which is what lets a correlation rule pair
    `load_average_high` with `threat_outbound_c2` without any component
    knowing the other exists.
    """
    findings, not_checked, ran, missing, snapshot, health_score = _run_engines(
        diagnostics, network
    )

    threat_summary = ""
    if threat is not None and connections is not None:
        matched, threat_summary, checked = _threat_findings(threat, connections)
        findings += matched
        (ran if checked else missing).append("threat-feeds")

    if findings:
        _normalise_machine_id(findings, findings[0].machine_id)

    return Gathered(
        threat_summary=threat_summary,
        findings=findings,
        not_checked=not_checked,
        engines_run=tuple(ran),
        engines_missing=tuple(missing),
        snapshot=snapshot,
        health_score=health_score,
    )
