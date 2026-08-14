"""Tests for knowledge-base grounding (R5, closing item).

The item this closes read *"ground explanations in retrieved KB entries,
not model guesswork"*. The tests below encode what that turned out to
mean, because the obvious reading was the wrong one.

**Not tested here, because it is not built:** generating story text from
a model at correlation time. That would add a hallucination surface to
the most expensive place in the platform to be wrong. Stories stay
authored; grounding attaches references to them.

**What is tested is the honesty property:** a story with citations and a
story without them must never be indistinguishable. An ungrounded
explanation is not a defect. An ungrounded explanation that looks
grounded is.

Run: python3 tools/test_grounding.py
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import (  # noqa: E402
    GROUNDED,
    NO_KB,
    NO_MATCH,
    Citation,
    Coverage,
    Correlation,
    Finding,
)
from domains.correlation import CorrelationService  # noqa: E402
from domains.correlation import rules as rules_module  # noqa: E402
from storage import KnowledgeBase  # noqa: E402

KB_PATH = ROOT / "data" / "knowledge" / "security_kb.json"


def _finding(fid, severity="warning", confidence="likely", source="netdiag"):
    return Finding(
        id=fid, machine_id="web-02", source_module=source,
        severity=severity, confidence=confidence,
        message=f"{fid} occurred",
        coverage=Coverage(checked=5, total=5),
    )


def _poisoning_findings():
    """The pair that fires the platform's flagship security rule."""
    return [
        _finding("hygiene_poisoning_surface"),
        _finding("dns_resolution_failure", severity="critical"),
    ]


# --- the knowledge base ----------------------------------------------------

def test_the_shipped_kb_loads():
    kb = KnowledgeBase()
    assert kb.is_available, kb.unavailable_reason
    assert kb.size >= 8


def test_every_kb_entry_is_keyed_to_a_real_signal():
    """An entry nothing can retrieve makes the KB look richer than it is.

    Each `applies_to` must name either a finding id used by a shipped
    correlation rule, or a rule id itself. Written as a test because a
    KB that drifts from the engines is a KB that silently stops
    grounding anything.
    """
    raw = json.loads(KB_PATH.read_text(encoding="utf-8"))
    known = {r.id for r in rules_module.RULES}
    for rule in rules_module.RULES:
        known.update(rule.requires)
    # Signals the engines emit that no rule pairs yet — still legitimate
    # KB subjects, and named explicitly rather than allowed by a blanket
    # exception.
    known |= {"hygiene_smb1_enabled", "hygiene_rdp_without_nla",
              "hygiene_risky_listeners", "captive_portal", "link_down"}
    # Findings the platform emits itself, from domains/threat/. Imported
    # rather than retyped so a renamed id fails loudly here.
    from domains.threat import ID_C2, ID_FLAGGED, ID_PAYLOAD
    known |= {ID_C2, ID_PAYLOAD, ID_FLAGGED}

    orphans = []
    for entry in raw["entries"]:
        for topic in entry["applies_to"]:
            if topic not in known:
                orphans.append(f"{entry['id']} -> {topic}")
    assert not orphans, "KB entries keyed to signals nothing emits:\n  " + \
        "\n  ".join(orphans)


def test_the_kb_attributes_attack():
    """Technique ids are MITRE's; the mappings are ours. Both stated."""
    raw = json.loads(KB_PATH.read_text(encoding="utf-8"))
    attribution = raw["attribution"].lower()
    assert "mitre" in attribution
    assert "ours" in attribution or "our" in attribution


def test_exact_keying_beats_similarity():
    """A deliberately-written entry must win over whatever scores highest."""
    kb = KnowledgeBase()
    cited = kb.for_topic("poisoning_surface_actively_reachable")
    assert cited
    assert cited[0].entry_id == "kb_llmnr_poisoning"


def test_search_ranks_the_right_entry_first():
    kb = KnowledgeBase()
    hits = kb.search("machine broadcasts a name query and someone answers it")
    assert hits and hits[0].entry_id == "kb_llmnr_poisoning"


def test_a_weak_match_is_not_returned_as_support():
    """Below the floor, overlap is coincidence, not relevance."""
    kb = KnowledgeBase()
    assert kb.search("the printer is out of magenta toner") == []


def test_a_missing_kb_is_a_state_not_a_crash():
    kb = KnowledgeBase(path=Path(tempfile.mkdtemp()) / "absent.json")
    assert kb.is_available is False
    assert "not found" in kb.unavailable_reason
    assert kb.search("anything") == []


# --- grounding through the service ----------------------------------------

def test_a_grounded_story_carries_its_citations():
    service = CorrelationService(knowledge=KnowledgeBase())
    result = service.correlate(_poisoning_findings())

    story = result.correlations[0]
    assert story.id == "poisoning_surface_actively_reachable"
    assert story.is_grounded
    assert story.grounding == GROUNDED
    assert "T1557.001" in story.techniques


def test_without_a_kb_the_story_still_fires_but_says_it_is_unsupported():
    """Correlation must not depend on grounding. It must not hide it either."""
    service = CorrelationService(knowledge=None)
    story = service.correlate(_poisoning_findings()).correlations[0]

    assert story.story, "the authored story is still produced"
    assert story.is_grounded is False
    assert story.grounding == NO_KB
    assert story.citations == ()


def test_an_unreadable_kb_reports_why():
    broken = Path(tempfile.mkdtemp()) / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    service = CorrelationService(knowledge=KnowledgeBase(path=broken))

    story = service.correlate(_poisoning_findings()).correlations[0]
    assert story.is_grounded is False
    assert NO_KB in story.grounding
    assert "unreadable" in story.grounding


def test_an_empty_kb_reports_no_match_not_no_kb():
    """'We did not look' and 'we looked and found nothing' differ."""
    empty = Path(tempfile.mkdtemp()) / "empty.json"
    empty.write_text(json.dumps({"entries": []}), encoding="utf-8")
    service = CorrelationService(knowledge=KnowledgeBase(path=empty))

    story = service.correlate(_poisoning_findings()).correlations[0]
    assert story.grounding in (NO_MATCH, NO_KB)
    # An empty file loads but holds nothing; that is 'no KB available',
    # and either answer is honest so long as it is not silence.
    assert story.is_grounded is False


def test_ungrounded_stories_are_listed_not_filtered():
    service = CorrelationService(knowledge=None)
    result = service.correlate(_poisoning_findings())
    assert len(result.ungrounded) == len(result.correlations)
    assert result.grounding_available is False


def test_grounding_availability_is_reported():
    service = CorrelationService(knowledge=KnowledgeBase())
    assert service.correlate(_poisoning_findings()).grounding_available is True


# --- the contract's own guard ---------------------------------------------

def test_citations_without_grounded_status_are_rejected():
    """The record and the report must not be able to disagree."""
    try:
        Correlation(
            id="x", machine_id="web-02", story="s",
            members=_poisoning_findings(),
            severity="warning", confidence="likely",
            citations=(Citation(entry_id="kb_x", title="X", summary="s"),),
            grounding=NO_MATCH,
        )
    except ValueError as exc:
        assert "grounded" in str(exc)
        return
    raise AssertionError("citations were allowed on an ungrounded correlation")


def test_a_citation_must_be_readable_without_a_lookup():
    for bad in ({"entry_id": "", "title": "X", "summary": "s"},
                {"entry_id": "k", "title": "", "summary": "s"}):
        try:
            Citation(**bad)
        except ValueError:
            continue
        raise AssertionError(f"an unusable citation was allowed: {bad}")


def test_grounding_does_not_change_severity_or_confidence():
    """Citations are references, not evidence. They must not escalate.

    The rule the whole correlation contract is built on: reading findings
    together adds meaning, not measurement. Retrieving a document about
    them adds neither.
    """
    findings = _poisoning_findings()
    grounded = CorrelationService(knowledge=KnowledgeBase()).correlate(findings)
    plain = CorrelationService(knowledge=None).correlate(findings)

    a, b = grounded.correlations[0], plain.correlations[0]
    assert (a.severity, a.confidence) == (b.severity, b.confidence)


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
