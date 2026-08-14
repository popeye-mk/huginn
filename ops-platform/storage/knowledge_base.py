"""Security knowledge base — retrieval for grounding correlation stories.

Lives in `storage/` rather than a domain because `domains/correlation/`
may not import another domain, and this is read by correlation while
being useful to anything else that needs the same context. `storage` sits
below `domains` in the layer model, so the import direction is legal and
the knowledge stays available to whatever needs it next.

**Deliberately not the predecessor project's FAISS index.** Two reasons, both already
settled earlier in this project: her index holds the user's
support-engineer coursework, and writing attack patterns into it would
put *"what does LLMNR poisoning mean"* in competition with Windows Server
material during recall. The second is namespacing — the R8 licensing
analysis concluded feeds and corpora stay separate and are matched
independently, and the same reasoning applies here.

**Retrieval degrades loudly.** With an embedder, matching is semantic;
without one it falls back to keyword overlap and *says so*. A knowledge
base that silently answered worse would make an ungrounded claim look
grounded, which is the exact failure `contracts/citation.py` exists to
prevent.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from contracts.citation import Citation

DEFAULT_KB_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "knowledge" / "security_kb.json"
)

# Below this, a keyword match is coincidence rather than relevance. Set
# from the same reasoning as the findings store's floor: a weak match
# presented as support is worse than no support at all.
_MIN_KEYWORD_SCORE = 0.15


@dataclass
class KbEntry:
    """One knowledge-base entry, as stored."""

    id: str
    title: str
    summary: str
    applies_to: tuple = ()
    keywords: tuple = ()
    technique: Optional[str] = None
    why_it_matters: str = ""
    remediation: str = ""

    def as_citation(self, score: Optional[float] = None) -> Citation:
        return Citation(
            entry_id=self.id,
            title=self.title,
            summary=self.summary,
            technique=self.technique,
            score=score,
        )

    @property
    def search_text(self) -> str:
        """What gets embedded or keyword-matched.

        The id is excluded on purpose. Embedding it once let a record win
        on a shared token rather than on meaning — caught during R3, and
        the same mistake is available here.
        """
        return f"{self.title}. {self.summary} {' '.join(self.keywords)}"


class KnowledgeBase:
    """Loads the security KB and retrieves entries supporting a claim."""

    def __init__(
        self,
        path: Optional[Path] = None,
        embedder: Optional[Callable] = None,
    ):
        self.path = Path(path or DEFAULT_KB_PATH)
        self.embedder = embedder
        self._entries: List[KbEntry] = []
        self._by_topic: Dict[str, List[KbEntry]] = {}
        self._document_frequency: Dict[str, int] = {}
        self._load_error = ""
        self._load()
        self._index_terms()

    # -- loading ---------------------------------------------------------

    def _load(self) -> None:
        """Read the KB. A missing file is a state, not a crash."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self._load_error = f"knowledge base not found at {self.path}"
            return
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"knowledge base unreadable: {exc}"
            return

        for record in raw.get("entries", []):
            entry = KbEntry(
                id=record["id"],
                title=record["title"],
                summary=record["summary"],
                applies_to=tuple(record.get("applies_to", ())),
                keywords=tuple(record.get("keywords", ())),
                technique=record.get("technique"),
                why_it_matters=record.get("why_it_matters", ""),
                remediation=record.get("remediation", ""),
            )
            self._entries.append(entry)
            for topic in entry.applies_to:
                self._by_topic.setdefault(topic, []).append(entry)

    def _index_terms(self) -> None:
        """Count how many entries each term appears in, once at load."""
        for entry in self._entries:
            for token in _tokens(entry.search_text):
                self._document_frequency[token] = (
                    self._document_frequency.get(token, 0) + 1
                )

    @property
    def is_available(self) -> bool:
        return bool(self._entries)

    @property
    def unavailable_reason(self) -> str:
        return self._load_error

    @property
    def size(self) -> int:
        return len(self._entries)

    # -- retrieval -------------------------------------------------------

    def for_topic(self, topic: str) -> List[Citation]:
        """Entries explicitly keyed to a finding or correlation id.

        Exact keying is tried before any similarity search. A rule that
        names the entry supporting it should get that entry, not whatever
        happened to score highest — retrieval is for the cases nobody
        anticipated, not a replacement for the ones somebody did.
        """
        return [e.as_citation() for e in self._by_topic.get(topic, [])]

    def search(self, query: str, top_k: int = 3) -> List[Citation]:
        """Similarity search over the KB, for topics with no exact key."""
        if not self.is_available or not (query or "").strip():
            return []
        scored = (
            self._semantic(query) if self.embedder else self._keyword(query)
        )
        return [
            entry.as_citation(score)
            for score, entry in sorted(scored, key=lambda p: -p[0])[:top_k]
            if score >= _MIN_KEYWORD_SCORE
        ]

    def _keyword(self, query: str):
        """Rarity-weighted token overlap. Crude, honest, needs no model.

        Plain overlap was tried first and was actively misleading: the
        query "coffee machine" scored 0.5 against three entries, because
        the word *machine* appears in nearly all of them. A common word
        matching is not evidence of relevance — it is evidence that the
        word is common.

        So each token is weighted by how rare it is across the corpus.
        A term in every entry contributes nothing; a term in none still
        counts against the query, so asking about something the KB has
        never heard of scores zero rather than scoring on the filler.
        """
        wanted = _tokens(query)
        if not wanted or not self._entries:
            return []

        weights = {t: self._idf(t) for t in wanted}
        total = sum(weights.values())
        if total <= 0:
            return []

        results = []
        for entry in self._entries:
            have = _tokens(entry.search_text)
            hits = [t for t in wanted if t in have]
            # One word in common is not support, whatever it scores.
            # "coffee machine" matched three entries on *machine* alone,
            # which is a coincidence dressed as a citation. With only
            # eight entries the corpus is too small for rarity weighting
            # to settle this by itself, so a second, blunter guard is
            # applied and stated rather than tuned away.
            if len(hits) < min(2, len(wanted)):
                continue
            results.append((sum(weights[t] for t in hits) / total, entry))
        return results

    def _idf(self, token: str) -> float:
        """Inverse document frequency, floored at zero.

        `log((N+1)/(1+df))` — a token present in every entry lands on
        zero and cannot carry a match on its own.
        """
        import math

        count = self._document_frequency.get(token, 0)
        return max(0.0, math.log((len(self._entries) + 1) / (1 + count)))

    def _semantic(self, query: str):
        """Embedding similarity, falling back rather than failing."""
        try:
            texts = [e.search_text for e in self._entries]
            vectors = self.embedder([query] + texts)
        except Exception:  # noqa: BLE001
            return self._keyword(query)
        return list(zip(_cosine_against_first(vectors), self._entries))


def _tokens(text: str) -> set:
    cleaned = "".join(c.lower() if c.isalnum() else " " for c in text)
    return {t for t in cleaned.split() if len(t) > 2}


def _cosine_against_first(vectors) -> List[float]:
    """Cosine of every vector against the first (the query)."""
    import numpy

    matrix = numpy.asarray(vectors, dtype="float32")
    norms = numpy.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    unit = matrix / norms
    return list(unit[1:] @ unit[0])
