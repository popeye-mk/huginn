"""KB lint tests (spec §12.3).

Two jobs: prove the linter catches the classes of rot it exists for,
and assert the *shipped* KB is clean — so a bad rule can't be committed
without a red test.
"""

import pytest

import kb_lint


def test_shipped_kb_is_clean():
    """The shipped knowledge base must pass its own linter."""
    issues = kb_lint.lint()
    errors = [i for i in issues if i.level == "error"]
    assert not errors, f"shipped KB has lint errors: {errors}"
    assert kb_lint.lint_exit_code(issues) == 0, [str(i) for i in issues]


def test_detects_duplicate_ids():
    rules = [
        {"id": "dup", "match": {"path": "disk.data.x", "op": "below", "value": 1},
         "finding": "a", "severity": "warning", "confidence": "certain", "next_step": "x"},
        {"id": "dup", "match": {"path": "disk.data.y", "op": "below", "value": 1},
         "finding": "b", "severity": "warning", "confidence": "certain", "next_step": "x"},
    ]
    messages = [i.message for i in kb_lint.check_rules(rules, [])]
    assert any("duplicate" in m for m in messages)


def test_detects_dangling_supersedes():
    rules = [{
        "id": "a", "match": {"path": "disk.data.x", "op": "below", "value": 1},
        "finding": "a", "severity": "warning", "confidence": "certain",
        "next_step": "x", "supersedes": ["does_not_exist"],
    }]
    messages = [i.message for i in kb_lint.check_rules(rules, [])]
    assert any("supersedes unknown rule" in m for m in messages)


def test_detects_circular_supersedes():
    common = {"match": {"path": "disk.data.x", "op": "below", "value": 1},
              "finding": "f", "severity": "warning", "confidence": "certain", "next_step": "x"}
    rules = [
        dict(id="a", supersedes=["b"], **common),
        dict(id="b", supersedes=["a"], **common),
    ]
    messages = [i.message for i in kb_lint.check_rules(rules, [])]
    assert any("circular" in m for m in messages)


def test_detects_missing_required_fields():
    rules = [{"id": "incomplete", "match": {"path": "disk.data.x", "op": "below", "value": 1},
              "finding": "f", "severity": "warning", "confidence": "certain"}]
    messages = [i.message for i in kb_lint.check_rules(rules, [])]
    assert any("next_step" in m for m in messages)


def test_detects_invalid_op_and_severity():
    rules = [{"id": "bad", "match": {"path": "disk.data.x", "op": "sideways", "value": 1},
              "finding": "f", "severity": "catastrophic", "confidence": "certain", "next_step": "x"}]
    messages = [i.message for i in kb_lint.check_rules(rules, [])]
    assert any("invalid match op" in m for m in messages)
    assert any("invalid severity" in m for m in messages)


def test_unreviewed_ticket_rule_must_be_quarantined():
    """§12.1 — a ticket-learned rule can't headline until reviewed."""
    rules = [{
        "id": "from_ticket", "match": {"path": "disk.data.x", "op": "below", "value": 1},
        "finding": "f", "severity": "critical", "confidence": "certain", "next_step": "x",
        "provenance": {"source": "ticket", "ticket_id": 4711, "reviewed_by": None},
    }]
    issues = kb_lint._check_rule_provenance(rules)
    assert any(i.level == "error" and "quarantined" in i.message for i in issues)


def test_reviewed_ticket_rule_is_allowed_to_headline():
    rules = [{
        "id": "from_ticket", "match": {"path": "disk.data.x", "op": "below", "value": 1},
        "finding": "f", "severity": "critical", "confidence": "certain", "next_step": "x",
        "provenance": {"source": "ticket", "ticket_id": 4711, "reviewed_by": "popeye-mk"},
    }]
    assert not kb_lint._check_rule_provenance(rules)


def test_quarantined_rule_is_fine_at_possible_confidence():
    rules = [{
        "id": "from_ticket", "match": {"path": "disk.data.x", "op": "below", "value": 1},
        "finding": "f", "severity": "warning", "confidence": "possible", "next_step": "x",
        "provenance": {"source": "ticket", "ticket_id": 4711, "reviewed_by": None},
    }]
    assert not kb_lint._check_rule_provenance(rules)


def test_detects_chain_naming_unknown_rule():
    chains = [{"id": "c", "when": ["a", "ghost"], "root": "a",
               "confidence": "likely", "story": "..."}]
    messages = [i.message for i in kb_lint.check_chains(chains, {"a"})]
    assert any("unknown rule" in m for m in messages)


def test_detects_chain_root_outside_its_members():
    chains = [{"id": "c", "when": ["a", "b"], "root": "c",
               "confidence": "likely", "story": "..."}]
    messages = [i.message for i in kb_lint.check_chains(chains, {"a", "b", "c"})]
    assert any("not among its own" in m for m in messages)


def test_detects_triage_pointing_at_nothing():
    """The v4 regression this check exists for (§12.3)."""
    profiles = [{"symptom": "slow", "collectors": ["thermal"], "weight": ["thermal_throttle"]}]
    messages = [i.message for i in kb_lint.check_triage(profiles, {"disk_free_critical"}, {"disk"})]
    assert any("unknown collector 'thermal'" in m for m in messages)
    assert any("weights unknown rule 'thermal_throttle'" in m for m in messages)
