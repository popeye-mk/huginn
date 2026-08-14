"""Tests for the netdiag → Finding mapping.

Run against **captured real netdiag output** (`tools/fixtures/`), not
invented data. netdiag's own project review makes the case for this
better than I could: nineteen of its twenty field bugs were the tool
being confidently wrong, and they were found by running it rather than
by reading it.

Run: python3 tools/test_network_mapping.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.network import mapping  # noqa: E402

ROOT_PARENT = ROOT.parent
FIXTURE = ROOT / "tools" / "fixtures" / "netdiag_live.json"


def _payload():
    return json.loads(FIXTURE.read_text())


def test_findings_map_with_required_fields():
    findings = mapping.to_findings(_payload())
    assert findings, "fixture should contain findings"
    for f in findings:
        assert f.source_module == "netdiag"
        assert f.machine_id
        assert f.message
        assert f.severity in ("critical", "warning", "info")
        assert f.confidence in ("certain", "likely", "possible")


def test_hygiene_rules_are_tagged_security():
    """The whole cross-signal thesis depends on this tag existing."""
    findings = mapping.to_findings(_payload())
    hygiene = [f for f in findings if f.id.startswith("hygiene_")]

    assert hygiene, "fixture should contain at least one hygiene finding"
    for f in hygiene:
        assert f.is_security, f"{f.id} should be tagged security"


def test_non_hygiene_findings_are_not_security():
    findings = mapping.to_findings(_payload())
    for f in findings:
        if not mapping.is_security_rule(f.id):
            assert not f.is_security, f"{f.id} wrongly tagged security"


def test_security_classification_is_explicit_not_text_matching():
    """Classification reads rule ids, not rule wording.

    Matching on text would silently reclassify a rule the moment someone
    rewords it — the kind of drift that is invisible until it matters.
    """
    assert mapping.is_security_rule("hygiene_smb1_enabled")
    assert mapping.is_security_rule("dns_hijack")
    assert not mapping.is_security_rule("link_down")
    assert not mapping.is_security_rule("dns_resolution_failure")


def test_security_rule_ids_exist_in_netdiags_knowledge_base():
    """Guard against classifying findings that no engine emits.

    An earlier version listed `rogue_dhcp` and `dns_hijack_suspected`,
    neither of which netdiag has. Nothing failed — the classification
    simply never applied, which is the quiet kind of wrong.
    """
    import json
    kb = (ROOT.parent / "network" / "netdiag_v1" / "kb" / "rules.json")
    if not kb.exists():
        print("      SKIP: netdiag sibling absent — cannot cross-check its "
              "rule ids. Unverified, not verified-clean.")
        return
    data = json.loads(kb.read_text())
    rules = data if isinstance(data, list) else data.get("rules", [])
    known = {r["id"] for r in rules if "id" in r}

    unknown = [rid for rid in mapping.SECURITY_RULE_IDS if rid not in known]
    assert not unknown, f"security ids netdiag never emits: {unknown}"


def test_osi_layer_is_preserved_as_a_tag():
    findings = mapping.to_findings(_payload())
    layered = [f for f in findings if any(t.startswith("layer:") for t in f.tags)]
    assert layered, "netdiag layers should survive mapping"


def test_plain_language_text_is_preserved():
    """netdiag's for_user copy is its best asset; dropping it would be a loss."""
    findings = mapping.to_findings(_payload())
    with_plain = [f for f in findings if f.plain_message]

    assert with_plain, "for_user text should be carried through"
    for f in with_plain:
        assert f.for_display() == f.plain_message


def test_for_display_falls_back_rather_than_inventing():
    """A finding with no plain text returns the technical text unchanged."""
    from contracts import Coverage, Finding

    f = Finding(
        id="x", source_module="netdiag", machine_id="h",
        severity="warning", confidence="likely",
        message="technical wording", coverage=Coverage(1, 1),
    )
    assert f.plain_message is None
    assert f.for_display() == "technical wording"


def test_coverage_counts_only_collectors_that_ran():
    payload = _payload()
    coverage = mapping.extract_coverage(payload)
    collectors = payload["snapshot"]["collectors"]

    ran = sum(1 for c in collectors.values() if c.get("status") == "ok")
    assert coverage.checked == ran
    assert coverage.total == len(collectors)
    assert coverage.checked < coverage.total, (
        "this fixture has skipped collectors; if not, pick another"
    )


def test_missing_collectors_yield_zero_knowledge_not_full_coverage():
    """The failure that matters: no data must never read as 'all checked'."""
    coverage = mapping.extract_coverage({})
    assert coverage.checked == 0
    assert coverage.total == 0


def test_skipped_collectors_are_reported():
    not_checked = mapping.extract_not_checked(_payload())
    assert not_checked, "skipped collectors must be surfaced, not dropped"
    for name, status, _reason in not_checked:
        assert name
        assert status != "ok"


def test_malformed_finding_is_skipped_not_fatal():
    payload = _payload()
    payload["findings"] = list(payload["findings"]) + [
        {"id": "bad", "severity": "nope", "confidence": "certain", "finding": "x"}
    ]
    findings = mapping.to_findings(payload)
    assert all(f.id != "bad" for f in findings)
    assert findings, "valid findings must survive a malformed neighbour"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
