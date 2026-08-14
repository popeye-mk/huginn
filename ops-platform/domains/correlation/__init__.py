"""Cross-signal correlation — several findings read as one story.

Depends on the `Finding` contract, not on the domains that produce them,
so it works against any engine that speaks the shared language.
"""

from .service import CorrelationService, TriageResult

__all__ = ["CorrelationService", "TriageResult"]
