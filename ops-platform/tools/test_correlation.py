"""Tests for cross-signal correlation.

Two jobs here, and the second one matters more than the first.

**1. The safety rails hold.** A correlation must never be more confident
or more severe than the findings it is built from. This is the one place
the platform could quietly start inventing certainty, so the caps are
tested directly rather than trusted.

**2. No rule is dead.** Every correlation rule is validated against the
*real* knowledge bases of both engines. This check exists because three
of the first four rules referenced IDs that did not exist — including
`dns_failure` where Diagnostic Companion actually emits
`dns_resolution_failing`, one letter from netdiag's
`dns_resolution_failure`. A rule that can never fire is worse than no
rule: it makes the rule set look richer than it is, and nothing tells
you otherwise.

Run: python3 tools/test_correlation.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import Coverage, Correlation, Finding  # noqa: E402
from domains.correlation import CorrelationService  # noqa: E402
from domains.correlation import rules as rules_module  # noqa: E402

NETDIAG_KB = ROOT.parent / "network" / "netdiag_v1" / "kb" / "rules.json"
DC_KB_DIR = (
    ROOT.parent / "diagnostics" / "diagnostic-companion-v1.3"
    / "diagnostic-companion" / "pattern_kb"
)


def _finding(fid, severity="warning", confidence="likely", **kw):
    base = dict(
        id=fid, source_module="netdiag", machine_id="host-a",
        severity=severity, confidence=confidence,
        message=f"{fid} message", coverage=Coverage(checked=5, total=10),
    )
    base.update(kw)
    return Finding(**base)


# --- safety rails ---------------------------------------------------------

def test_correlation_cannot_claim_more_confidence_than_members():
    members = [
        _finding("a", confidence="likely"),
        _finding("b", confidence="possible"),
    ]
    try:
        Correlation(
            id="c", machine_id="host-a", story="s", members=members,
            severity="warning", confidence="certain",
        )
    except ValueError as exc:
        assert "weakest member" in str(exc)
        return
    raise AssertionError("manufactured certainty was accepted")


def test_correlation_cannot_claim_more_severity_than_members():
    members = [_finding("a", severity="warning"), _finding("b", severity="warning")]
    try:
        Correlation(
            id="c", machine_id="host-a", story="s", members=members,
            severity="critical", confidence="likely",
        )
    except ValueError as exc:
        assert "adds meaning, not urgency" in str(exc)
        return
    raise AssertionError("two warnings were alchemised into a critical")


def test_correlation_requires_at_least_two_findings():
    try:
        Correlation(
            id="c", machine_id="host-a", story="s",
            members=[_finding("a")], severity="warning", confidence="likely",
        )
    except ValueError as exc:
        assert "just a finding" in str(exc)
        return
    raise AssertionError("a single finding was accepted as a correlation")


def test_coverage_is_the_worst_of_the_members():
    """A story is only as complete as its least-examined part."""
    members = [
        _finding("a", coverage=Coverage(checked=9, total=10)),
        _finding("b", coverage=Coverage(checked=2, total=10)),
    ]
    corr = Correlation(
        id="c", machine_id="host-a", story="s", members=members,
        severity="warning", confidence="likely",
    )
    assert corr.coverage.checked == 2


def test_rule_confidence_is_capped_by_data_not_by_declaration():
    """A rule may declare `certain`; weak data must still downgrade it."""
    rule = rules_module.CorrelationRule(
        id="r", requires=("a", "b"), severity="warning",
        confidence="certain", story="s",
    )
    by_id = {
        "a": _finding("a", confidence="certain"),
        "b": _finding("b", confidence="possible"),
    }
    corr = rule.build(by_id, "host-a")
    assert corr.confidence == "possible"


# --- no dead rules --------------------------------------------------------

_SKIPPED = []


def _platform_ids():
    """Findings this platform emits itself, not read from an engine.

    `threat_outbound_c2` and friends come from `domains/threat/`, which
    matches observed connections against threat feeds. They are as real
    as any engine finding — the KB check would otherwise reject a rule
    for referencing a signal the platform definitely produces.

    Imported rather than retyped so the two cannot drift apart.
    """
    from domains.threat import ID_C2, ID_FLAGGED, ID_PAYLOAD

    return {ID_C2, ID_PAYLOAD, ID_FLAGGED}


def _netdiag_ids():
    """netdiag's finding ids, or None if its KB is not beside this repo.

    netdiag is a SEPARATE project. Cloned on its own, this repo has no
    sibling to read — and this project's own rule applies to its own test
    harness: a check that cannot see the evidence reports it could not
    check, it does not crash or convict.
    """
    if not NETDIAG_KB.exists():
        return None
    data = json.loads(NETDIAG_KB.read_text())
    rules = data if isinstance(data, list) else data.get("rules", [])
    return {r["id"] for r in rules if "id" in r}


def _dc_ids():
    try:
        import yaml
    except ImportError:
        return None
    ids = set()
    for path in DC_KB_DIR.glob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        rules = (
            data if isinstance(data, list)
            else (data.get("rules") or data.get("entries")
                  or data.get("chains") or [])
        )
        ids.update(r["id"] for r in rules if isinstance(r, dict) and "id" in r)
    return ids


def test_every_rule_references_real_finding_ids():
    """The check that would have caught three broken rules on day one.

    **Without PyYAML this test cannot see Diagnostic Companion's
    knowledge base**, which is YAML. The first Windows run showed why
    that matters: it fell back to netdiag's KB alone and then failed,
    accusing `dns_failure_confirmed_by_both_engines` of referencing a
    finding "no engine emits" — when the truth was that the test could
    not read the engine that emits it.

    That is this project's own rule broken backwards. Everywhere else,
    absence is never treated as health; here absence was treated as
    *disease*. A check that cannot see half the evidence must report
    that it could not check, not convict on the half it saw.
    """
    nd = _netdiag_ids()
    if nd is None:
        print(
            "      SKIP: the netdiag sibling project is not beside this repo, "
            "so its rule ids cannot be validated. Unverified, not "
            "verified-clean. Clone netdiag alongside to run this."
        )
        _SKIPPED.append("rule id validation (netdiag sibling absent)")
        return
    known = nd | _platform_ids()
    dc = _dc_ids()
    if dc is None:
        print(
            "      SKIP: PyYAML absent — Diagnostic Companion's knowledge "
            "base could not be read, so rule ids cannot be validated. "
            "This is unverified, not verified-clean. Install pyyaml."
        )
        _SKIPPED.append("rule id validation (PyYAML absent)")
        return
    known |= dc

    unknown = []
    for rule in rules_module.RULES:
        for fid in rule.requires:
            if fid not in known:
                unknown.append(f"{rule.id} requires unknown finding {fid!r}")

    assert not unknown, (
        "Rules referencing findings no engine emits:\n  " + "\n  ".join(unknown)
    )


def test_suppressed_ids_are_also_required_by_their_rule():
    """A rule cannot suppress a finding it does not itself depend on."""
    bad = [
        f"{r.id} suppresses {fid!r} which it does not require"
        for r in rules_module.RULES
        for fid in r.suppresses
        if fid not in r.requires
    ]
    assert not bad, "\n  ".join(bad)


# --- service behaviour ----------------------------------------------------

def test_findings_from_different_machines_are_not_correlated():
    """Two machines failing DNS is a fleet fact, not one machine's story."""
    findings = [
        _finding("hygiene_poisoning_surface", machine_id="host-a"),
        _finding("dns_resolution_failure", machine_id="host-b"),
    ]
    result = CorrelationService().correlate(findings, machine_id="host-a")
    assert not result.correlations


def test_single_engine_is_reported_as_untested_not_all_clear():
    findings = [_finding("link_down", severity="critical", confidence="certain")]
    result = CorrelationService().correlate(findings)
    assert result.is_single_source


def test_suppressed_findings_are_kept_not_deleted():
    """A reader must be able to check the reasoning."""
    findings = [
        _finding("captive_portal", severity="critical", confidence="certain"),
        _finding("dns_resolution_failure", severity="critical", confidence="likely"),
    ]
    result = CorrelationService().correlate(findings)

    assert result.correlations
    assert "dns_resolution_failure" in result.suppressed_ids
    assert any(f.id == "dns_resolution_failure" for f in result.findings)
    assert all(f.id != "dns_resolution_failure" for f in result.standalone_findings)


def test_cross_source_is_distinguished_from_single_source():
    findings = [
        _finding("dns_resolution_failing", source_module="diagnostic-companion",
                 severity="critical", confidence="certain"),
        _finding("dns_resolution_failure", source_module="netdiag",
                 severity="critical", confidence="certain"),
    ]
    result = CorrelationService().correlate(findings)

    assert result.correlations, "cross-engine agreement rule should fire"
    corr = result.correlations[0]
    assert corr.is_cross_source
    assert corr.sources == ("diagnostic-companion", "netdiag")


def test_security_correlation_is_flagged():
    findings = [
        _finding("hygiene_poisoning_surface", tags=("security",)),
        _finding("dns_resolution_failure", severity="critical",
                 confidence="likely"),
    ]
    result = CorrelationService().correlate(findings)
    assert result.security_correlations


def test_empty_input_produces_no_stories():
    result = CorrelationService().correlate([])
    assert not result.correlations
    assert result.is_single_source


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    # A skipped test is not a passed test. Counting them together is the
    # exact failure this platform exists to prevent, and it was sitting
    # in the runner that checks for it: on Windows without numpy this
    # printed "17 tests passed" while one had verified nothing.
    print(f"\n{passed - len(_SKIPPED)} tests passed, {len(_SKIPPED)} skipped")
    for skipped in _SKIPPED:
        print(f"  skipped (UNVERIFIED): {skipped}")
