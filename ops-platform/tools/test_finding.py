"""Tests for the shared finding schema.

Run: python3 -m pytest schema/test_finding.py -q
 or: python3 schema/test_finding.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from contracts import Coverage, Finding, sort_findings  # noqa: E402


def _finding(**overrides):
    base = dict(
        id="disk-low-01",
        source_module="diagnostic-companion",
        machine_id="laptop-01",
        severity="critical",
        confidence="certain",
        message="Disk space is critically low.",
        coverage=Coverage(checked=7, total=11),
        suggested_action="Clear space now or expand the volume.",
    )
    base.update(overrides)
    return Finding(**base)


def test_valid_finding_roundtrips_through_dict():
    original = _finding()
    restored = Finding.from_dict(original.to_dict())
    assert restored.id == original.id
    assert restored.message == original.message
    assert restored.coverage.checked == 7
    assert restored.coverage.total == 11


def test_invalid_values_are_rejected():
    for bad in (
        dict(severity="catastrophic"),
        dict(confidence="pretty-sure"),
        dict(source_module="some-tool"),
        dict(message=""),
    ):
        try:
            _finding(**bad)
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {bad}")


def test_coverage_cannot_claim_more_checked_than_total():
    try:
        Coverage(checked=12, total=11)
    except ValueError:
        return
    raise AssertionError("coverage should reject checked > total")


def test_possible_confidence_can_never_headline():
    assert _finding(confidence="possible").can_headline is False
    assert _finding(confidence="likely").can_headline is True
    assert _finding(confidence="certain").can_headline is True


def test_only_certain_criticals_are_actionable():
    assert _finding(severity="critical", confidence="certain").is_actionable
    assert not _finding(severity="critical", confidence="likely").is_actionable
    assert not _finding(severity="warning", confidence="certain").is_actionable


def test_incomplete_coverage_is_visible():
    partial = _finding(coverage=Coverage(checked=7, total=11))
    complete = _finding(coverage=Coverage(checked=11, total=11))
    assert partial.coverage.is_complete is False
    assert complete.coverage.is_complete is True
    assert str(partial.coverage) == "7/11 checked"


def test_findings_sort_worst_and_most_certain_first():
    findings = [
        _finding(id="c", severity="info", confidence="certain"),
        _finding(id="b", severity="critical", confidence="possible"),
        _finding(id="a", severity="critical", confidence="certain"),
        _finding(id="d", severity="warning", confidence="likely"),
    ]
    assert [f.id for f in sort_findings(findings)] == ["a", "b", "d", "c"]


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
