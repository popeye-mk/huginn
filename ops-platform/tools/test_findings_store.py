"""Tests for the findings store and recall (R3).

Two properties matter most here and are tested directly:

**Occurrences, not appends.** Running triage fifty times must produce
one record seen fifty times, not fifty records. Get this wrong and the
history becomes unreadable exactly when it becomes useful.

**Isolation from the predecessor project's memory.** Findings live in their own file and
are recalled only from findings. Answering "what broke last week" with
a chunk of Windows Server coursework is how a knowledge base loses
trust.

Run: python3 tools/test_findings_store.py
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# numpy is a genuine optional dependency: semantic recall needs it,
# substring recall does not, and the store is written to degrade to the
# latter and say so. The first Windows run failed this whole suite at
# import — 17 tests lost, including every non-numpy one, because a
# hard import declared an optional dependency mandatory.
try:
    import numpy as np  # noqa: E402
    HAVE_NUMPY = True
except ImportError:  # noqa: BLE001
    np = None
    HAVE_NUMPY = False


_SKIPPED = []


def _needs_numpy():
    """Report a skipped test as skipped, never as a pass."""
    if not HAVE_NUMPY:
        print("      SKIP: numpy absent — semantic recall unverified here")
        _SKIPPED.append("semantic recall (numpy absent)")
        return True
    return False

from contracts import Correlation, Coverage, Finding  # noqa: E402
from storage import FindingsStore, recall  # noqa: E402
from storage.findings_recall import (  # noqa: E402
    SEMANTIC,
    SUBSTRING,
    RecallHit,
    apply_adaptive_threshold,
)
from storage.findings_store import StoredRecord  # noqa: E402


def _store(embedder=None) -> FindingsStore:
    path = Path(tempfile.mkdtemp()) / "findings.json"
    return FindingsStore(path, embedder=embedder).load()


def _finding(fid="disk_free_critical", machine="web-02", **kw):
    base = dict(
        id=fid, source_module="diagnostic-companion", machine_id=machine,
        severity="critical", confidence="certain",
        message="Disk space critically low", coverage=Coverage(4, 4),
    )
    base.update(kw)
    return Finding(**base)


def _fake_embedder(texts):
    """Deterministic bag-of-characters vectors — no ML stack needed."""
    out = []
    for text in texts:
        vec = np.zeros(64, dtype="float32")
        for ch in str(text).lower():
            vec[ord(ch) % 64] += 1.0
        out.append(vec)
    return np.array(out)


# --- storing --------------------------------------------------------------

def test_findings_are_persisted_and_reloadable():
    store = _store()
    store.record([_finding()])

    reloaded = FindingsStore(store.path).load()
    assert len(reloaded.all()) == 1
    assert reloaded.all()[0].record_id == "disk_free_critical"


def test_repeats_increment_rather_than_duplicate():
    """The property that makes history readable."""
    store = _store()
    for _ in range(50):
        store.record([_finding()])

    records = store.all()
    assert len(records) == 1, "50 runs must not create 50 records"
    assert records[0].times_seen == 50
    assert records[0].is_recurring


def test_repeat_keeps_the_newest_wording():
    """Messages carry current measurements; the latest reading is useful."""
    store = _store()
    store.record([_finding(message="4.0% free")])
    store.record([_finding(message="1.2% free")])

    assert store.all()[0].text == "1.2% free"


def test_first_seen_survives_repeats():
    store = _store()
    store.record([_finding()])
    original = store.all()[0].first_seen
    store.record([_finding()])

    record = store.all()[0]
    assert record.first_seen == original
    assert record.last_seen >= original


def test_same_id_on_different_machines_stays_separate():
    store = _store()
    store.record([_finding(machine="web-02"), _finding(machine="db-01")])

    assert len(store.all()) == 2
    assert len(store.for_machine("web-02")) == 1


def test_correlations_are_stored_alongside_findings():
    store = _store()
    members = [
        _finding("hygiene_poisoning_surface", severity="warning",
                 confidence="likely", tags=("security",)),
        _finding("dns_resolution_failure", confidence="likely"),
    ]
    corr = Correlation(
        id="poisoning_surface_actively_reachable", machine_id="web-02",
        story="Two signals, one situation.", members=members,
        severity="critical", confidence="likely",
    )
    store.record(members, [corr])

    namespaces = {r.namespace for r in store.all()}
    assert namespaces == {"finding", "correlation"}


def test_security_tag_survives_storage():
    store = _store()
    store.record([_finding("hygiene_smb1_enabled", tags=("security",))])
    assert store.security_records()


def test_recurring_is_ordered_by_frequency():
    store = _store()
    store.record([_finding("a"), _finding("b")])
    store.record([_finding("a")])
    store.record([_finding("a")])

    top = store.recurring()[0]
    assert top.record_id == "a"
    assert top.times_seen == 3


# --- recall ---------------------------------------------------------------

def test_recall_without_an_embedder_says_it_degraded():
    store = _store()
    store.record([_finding()])
    result = recall(store, "disk space")

    assert result.method == SUBSTRING
    assert result.degraded
    assert "no embedder" in result.reason
    assert "semantic recall unavailable" in result.summary


def test_recall_with_an_embedder_is_semantic():
    # The only test here that genuinely needs numpy: semantic recall
    # computes cosine similarity with it. Everything else in this file
    # exercises storage and substring recall, which do not.
    if _needs_numpy():
        return
    store = _store(embedder=_fake_embedder)
    store.record([_finding()])
    result = recall(store, "storage running out")

    assert result.method == SEMANTIC
    assert not result.degraded
    assert result.hits[0].is_semantic


def test_a_broken_embedder_falls_back_and_reports_why():
    def broken(texts):
        raise RuntimeError("model not loaded")

    store = _store(embedder=broken)
    store.record([_finding()])
    result = recall(store, "disk space")

    assert result.method == SUBSTRING
    assert result.degraded
    assert result.reason, "degrading without saying why is the failure mode"
    if HAVE_NUMPY:
        assert "model not loaded" in result.reason
    else:
        # Without numpy the semantic path fails *before* the embedder is
        # ever called, so the reason names numpy rather than the broken
        # embedder. Both are correct: what matters is that recall
        # degraded and said which dependency stopped it.
        assert "numpy" in result.reason.lower()


def test_recall_on_an_empty_store_returns_nothing_gracefully():
    result = recall(_store(), "anything")
    assert not result
    assert result.searched == 0


def test_recall_can_be_scoped_to_one_machine():
    store = _store()
    store.record([_finding(machine="web-02"), _finding(machine="db-01")])
    result = recall(store, "disk space", machine_id="db-01")

    assert all(h.record.machine_id == "db-01" for h in result.hits)


# --- adaptive threshold ---------------------------------------------------

def _hit(score):
    record = StoredRecord(
        key="k", namespace="finding", machine_id="m", record_id="r",
        text="t", severity="warning", confidence="likely",
        first_seen="", last_seen="",
    )
    return RecallHit(record, score, SEMANTIC)


def test_a_strong_top_hit_raises_the_cutoff():
    """Matches the predecessor project's RAGAS-tuned ladder: 0.95+ top → 0.80 cutoff."""
    kept = apply_adaptive_threshold([_hit(0.96), _hit(0.72), _hit(0.61)], 5)
    assert [round(h.score, 2) for h in kept] == [0.96]


def test_a_weak_top_hit_uses_the_floor():
    kept = apply_adaptive_threshold([_hit(0.66), _hit(0.62), _hit(0.41)], 5)
    assert [round(h.score, 2) for h in kept] == [0.66, 0.62]


def test_the_best_hit_survives_even_when_everything_is_weak():
    """'Closest thing, and it is weak' beats silence."""
    kept = apply_adaptive_threshold([_hit(0.31), _hit(0.22)], 5)
    assert len(kept) == 1
    assert round(kept[0].score, 2) == 0.31


def test_threshold_on_no_hits_returns_no_hits():
    assert apply_adaptive_threshold([], 5) == []


# --- E2: retention — age out stale one-offs, keep the history that matters --

def _aged(store, key, days_old):
    """Backdate a stored record's last_seen."""
    from datetime import datetime, timedelta, timezone
    rec = store._records[key]
    rec.last_seen = (datetime.now(timezone.utc) - timedelta(days=days_old)).isoformat()
    return rec


def test_prune_drops_a_stale_one_off():
    store = _store()
    store.record([_finding("old_blip")])
    key = list(store._records)[0]
    _aged(store, key, 400)
    removed = store.prune(older_than_days=180)
    assert removed == [key], "a 400-day-old one-off is aged out"
    assert not store.all(), "and it is gone from the store"


def test_prune_keeps_a_recent_one_off():
    store = _store()
    store.record([_finding("recent_blip")])
    assert store.prune(older_than_days=180) == [], "a fresh record is kept"
    assert len(store.all()) == 1


def test_prune_keeps_recurring_history_forever():
    store = _store()
    store.record([_finding("keeps_happening")])
    store.record([_finding("keeps_happening")])   # 2nd sighting
    key = list(store._records)[0]
    assert store._records[key].is_recurring, "seen twice"
    _aged(store, key, 900)
    assert store.prune(older_than_days=180) == [], "recurring history is never aged out"


def test_prune_keeps_security_records():
    store = _store()
    store.record([_finding("old_exposure", tags=("security",))])
    key = list(store._records)[0]
    _aged(store, key, 900)
    assert store.prune(older_than_days=180) == [], "a security finding is kept"


def test_prune_keeps_an_undateable_record():
    store = _store()
    store.record([_finding("weird_date")])
    key = list(store._records)[0]
    store._records[key].last_seen = "not-a-date"
    assert store.prune(older_than_days=1) == [], "a record we cannot date is not proven stale"


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
