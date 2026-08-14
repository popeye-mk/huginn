"""Persistence for the ops platform.

Owns its own files and index, separate from the predecessor project's memory store:
findings are machine-generated and unbounded, hers are learned facts and
reference material. Mixing them buries the irreplaceable under the
routine.
"""

from .findings_recall import RecallHit, RecallResult, recall
from .knowledge_base import KbEntry, KnowledgeBase
from .threat_feed import FeedStatus, ThreatFeed, load_feeds
from .findings_store import FindingsStore, RecordReport, StoredRecord

__all__ = [
    "FindingsStore", "StoredRecord", "RecordReport",
    "recall", "RecallResult", "RecallHit",
    "KnowledgeBase", "KbEntry",
    "ThreatFeed", "FeedStatus", "load_feeds",
]
