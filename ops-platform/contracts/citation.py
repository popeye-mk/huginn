"""Citations — where a claim came from. Pure data.

R5's open item was *"ground explanations in retrieved KB entries, not
model guesswork"*, and the honest reading of that took some getting to.

**What it does not mean:** generating the explanation from an LLM at
correlation time. That would add a hallucination surface to the one place
in the platform where a wrong claim is most expensive, and RAG reduces
hallucination without eliminating it. The correlation stories stay
authored, deterministic and reviewable.

**What it does mean:** a story that asserts "this is a Responder-style
credential capture precondition" must be able to show *what it is
standing on*. So each correlation carries citations retrieved from the
knowledge base at the moment it fired — and when nothing was retrieved,
it says so instead of presenting authored prose as though it were
sourced.

That second half is the whole point. An ungrounded explanation is not a
defect; **an ungrounded explanation that looks grounded is.**
"""

from dataclasses import asdict, dataclass
from typing import Optional

CONTRACT_VERSION = "0.1.0"

# Why a claim has no citations. Never collapsed into an empty list,
# because "we did not look" and "we looked and found nothing" send an
# admin to different places.
GROUNDED = "grounded"
NO_KB = "no knowledge base available"
NO_MATCH = "knowledge base searched, nothing matched"
NOT_REQUESTED = "grounding not requested"


@dataclass(frozen=True)
class Citation:
    """One knowledge-base entry supporting a claim."""

    entry_id: str
    title: str
    summary: str
    source: str = "huginn-security-kb"
    # ATT&CK technique this entry maps to, e.g. "T1557.001". Ours is the
    # mapping, not MITRE's — recorded as our claim about their taxonomy
    # rather than presented as though MITRE published it.
    technique: Optional[str] = None
    score: Optional[float] = None

    def __post_init__(self):
        if not self.entry_id:
            raise ValueError("a citation must name the entry it cites")
        if not self.title:
            raise ValueError("a citation must be readable without lookup")

    @property
    def label(self) -> str:
        """One-line reference for a report."""
        technique = f" [{self.technique}]" if self.technique else ""
        return f"{self.title}{technique}"

    def to_dict(self) -> dict:
        return asdict(self)
