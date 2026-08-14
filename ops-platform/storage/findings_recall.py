"""Semantic recall over stored findings.

Split from `findings_store` to keep each module to one job: that one
stores and counts, this one searches. The store must work with no ML
stack present; this module is the part that needs one.

**Recall degrades honestly.** With no embedder, `recall()` falls back to
substring matching and *says so* in the result, rather than returning
weaker answers that look identical to strong ones. That is the same rule
`memory_status` enforces for the predecessor project's memory, applied here: a search that
quietly got worse is indistinguishable from one that got no results, and
both look like "nothing happened".
"""

from dataclasses import dataclass
from typing import Any, List, Optional

from storage.findings_store import FindingsStore, StoredRecord

SEMANTIC = "semantic"
SUBSTRING = "substring"

# Adaptive confidence thresholds, matching the predecessor project's own
# `_apply_adaptive_threshold`. These values were tuned against RAGAS
# evaluation on her memory, and findings recall uses the same ladder so
# the two retrieval paths behave consistently — a 0.62 hit meaning
# "weak" in one place and "good" in the other is how a user stops
# trusting either number.
#
# The rule: the better the top hit, the stricter the cutoff. A strong
# match makes weak neighbours noise; a weak top hit means everything is
# uncertain and hiding the rest would overstate what was found.
_THRESHOLD_LADDER = ((0.95, 0.80), (0.85, 0.70))
_THRESHOLD_FLOOR = 0.60

# Below this, "best available" stops being a useful answer.
#
# Observed: a query for "dns" returned a finding at 0.08 under the header
# "Related to what you asked". It was the closest record, but 0.08 is not
# relatedness — it is the absence of a match, dressed up as one. Keeping
# the nearest neighbour is right when something is genuinely close and
# merely uncertain; presenting noise as a result is the overstatement this
# codebase exists to avoid.
_MEANINGLESS_BELOW = 0.15


def apply_adaptive_threshold(hits: List["RecallHit"], top_k: int) -> List["RecallHit"]:
    """Drop low-confidence hits relative to the best one.

    Never returns empty when there was a hit: if everything falls below
    the cutoff the single best is kept, because "here is the closest
    thing, and it is weak" is more useful than silence.
    """
    if not hits:
        return []

    ordered = sorted(hits, key=lambda h: -h.score)
    top = ordered[0].score

    threshold = _THRESHOLD_FLOOR
    for lower_bound, cutoff in _THRESHOLD_LADDER:
        if top >= lower_bound:
            threshold = cutoff
            break

    kept = [h for h in ordered if h.score >= threshold]
    if kept:
        return kept[: max(1, top_k)]

    # Nothing cleared the bar. Keep the closest only if it is close
    # enough to mean anything at all.
    return ordered[:1] if top >= _MEANINGLESS_BELOW else []


@dataclass
class RecallHit:
    """One recalled record, with how it was found."""

    record: StoredRecord
    score: float
    method: str

    @property
    def is_semantic(self) -> bool:
        return self.method == SEMANTIC


@dataclass
class RecallResult:
    """Hits plus an honest account of how the search was performed."""

    hits: List[RecallHit]
    method: str
    searched: int
    degraded: bool = False
    reason: str = ""

    def __bool__(self) -> bool:
        return bool(self.hits)

    @property
    def summary(self) -> str:
        if not self.hits and self.searched:
            return (
                f"Nothing related found among {self.searched} record(s) — "
                f"no match was close enough to be meaningful."
            )
        if self.degraded:
            return (
                f"{len(self.hits)} match(es) by {self.method} over "
                f"{self.searched} record(s) — semantic recall unavailable "
                f"({self.reason})."
            )
        return (
            f"{len(self.hits)} match(es) by {self.method} over "
            f"{self.searched} record(s)."
        )


def _substring_search(
    records: List[StoredRecord], query: str, top_k: int
) -> List[RecallHit]:
    """Crude fallback. Scores by how much of the query a record contains."""
    terms = [t for t in query.lower().split() if len(t) > 2]
    if not terms:
        return []

    hits = []
    for record in records:
        haystack = f"{record.record_id} {record.text}".lower()
        matched = sum(1 for term in terms if term in haystack)
        if matched:
            hits.append(RecallHit(record, matched / len(terms), SUBSTRING))

    hits.sort(key=lambda h: -h.score)
    return hits[:top_k]


def _semantic_search(
    store: FindingsStore, records: List[StoredRecord], query: str, top_k: int
) -> List[RecallHit]:
    """Embed the query and the records, rank by cosine similarity.

    Embeds on demand rather than maintaining a persisted index. With
    findings numbering in the hundreds this is fast enough, and it
    removes a whole class of staleness bug — the index cannot disagree
    with the store if there is no index. Worth revisiting only when the
    record count makes it slow.
    """
    import numpy as np

    # Embed the human sentence only, not the snake_case id.
    #
    # Including the id skewed ranking toward lexical overlap and away from
    # meaning: a query for "name resolution exposure" put
    # `dns_resolution_failing` first purely because its id contains the
    # token "resolution", while `hygiene_poisoning_surface` — which is
    # literally about name-resolution exposure — did not place at all.
    # Observed on real data. The id stays as the label; only the text is
    # embedded.
    texts = [r.text for r in records]
    vectors = store.embedder([query] + texts)
    vectors = np.asarray(vectors, dtype="float32")

    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    vectors = vectors / norms

    scores = vectors[1:] @ vectors[0]
    ranked = sorted(
        zip(records, scores), key=lambda pair: -float(pair[1])
    )[:top_k]
    return [RecallHit(rec, float(score), SEMANTIC) for rec, score in ranked]


def recall(
    store: FindingsStore,
    query: str,
    top_k: int = 5,
    machine_id: Optional[str] = None,
) -> RecallResult:
    """Find past findings related to a question.

    Scoped to findings only — never the predecessor project's reference corpus. "What was
    wrong with this machine last week" and "what did my course say about
    backups" are different questions, and answering the first with the
    second is how a knowledge base stops being trusted.
    """
    records = store.for_machine(machine_id) if machine_id else store.all()

    if not records:
        return RecallResult(hits=[], method=SUBSTRING, searched=0)

    if not store.can_recall:
        return RecallResult(
            hits=_substring_search(records, query, top_k),
            method=SUBSTRING,
            searched=len(records),
            degraded=True,
            reason="no embedder was provided",
        )

    try:
        hits = apply_adaptive_threshold(
            _semantic_search(store, records, query, top_k), top_k
        )
    except Exception as exc:  # noqa: BLE001 - report, never crash a query
        return RecallResult(
            hits=_substring_search(records, query, top_k),
            method=SUBSTRING,
            searched=len(records),
            degraded=True,
            reason=f"{type(exc).__name__}: {exc}",
        )

    return RecallResult(hits=hits, method=SEMANTIC, searched=len(records))
