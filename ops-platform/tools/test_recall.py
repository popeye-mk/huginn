"""Tests for M2 proactive recall — memory volunteering during triage.

The property under guard: recall NEVER pads. A history line requires a
real recurring record (course-note recall was retired 2026-07-26); and
nothing-to-say is said out loud, because absent recall and empty recall
are different facts.

Run: python3 tools/test_recall.py
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents import recalling  # noqa: E402
from agents.explaining import explain  # noqa: E402


class FakeFinding:
    def __init__(self, fid, title):
        self.id = fid
        self.title = title
        self.message = title
        self.is_actionable = False


class FakeRecord:
    def __init__(self, record_id, times_seen, first_seen):
        self.record_id = record_id
        self.times_seen = times_seen
        self.first_seen = first_seen

    @property
    def is_recurring(self):
        return self.times_seen > 1


class FakeStore:
    def __init__(self, records):
        self._records = records

    def for_machine(self, machine_id):
        return self._records




def test_history_line_requires_a_recurring_record():
    result = {"findings": [FakeFinding("disk_pressure", "disk pressure high")],
              "machine_id": "m1"}
    store = FakeStore([FakeRecord("disk_pressure", 3, "2026-05-01T00:00:00")])
    recalling.attach_recall(result, store)

    sections = result["recall"]["sections"]
    assert sections and "seen 3x" in sections[0]["history"]
    assert "2026-05-01" in sections[0]["history"]


def test_first_occurrence_gets_no_history_line():
    """Seen once is not a pattern; claiming history would be padding."""
    result = {"findings": [FakeFinding("disk_pressure", "disk pressure high")],
              "machine_id": "m1"}
    store = FakeStore([FakeRecord("disk_pressure", 1, "2026-07-01T00:00:00")])
    recalling.attach_recall(result, store)

    assert result["recall"]["sections"] == []
    assert "no past occurrences" in result["recall"]["note"] \
        or "no past occurrences" in result["recall"]["note"]


def test_recall_failure_never_breaks_triage():
    class ExplodingStore:
        def for_machine(self, machine_id):
            raise RuntimeError("boom")

    result = {"findings": [FakeFinding("f1", "x")], "machine_id": "m1"}
    recalling.attach_recall(result, ExplodingStore())
    assert "recall" in result  # and we got here without raising


def test_explain_renders_recall_and_absence():
    base = {"ok": True, "findings": [], "not_checked": [],
            "recall": {"sections": [
                {"finding": "disk pressure", "history": "seen 3x on this machine since 2026-05-01",
                 }],
                "note": ""}}
    text = explain(base)
    assert "seen 3x" in text

    empty = {"ok": True, "findings": [], "not_checked": [],
             "recall": {"sections": [], "note": "no past occurrences of these findings"}}
    text = explain(empty)
    assert "no past occurrences" in text


def test_no_findings_recalls_in_silence_not_a_hollow_note():
    """P1: `threat`/`backup` with no findings must not print an empty note.

    A clean check has nothing to recall against; a 'nothing matched' line
    there would imply memory was consulted when it never had a finding to
    consult it with.
    """
    result = {"findings": [], "machine_id": "m1"}
    recalling.attach_recall(result, FakeStore([]))
    assert result["recall"]["sections"] == []
    assert result["recall"]["note"] == ""


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
