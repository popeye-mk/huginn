"""Threat domain — comparing what this machine does against what is known bad.

Owns one question: *is this machine talking to somewhere it should not?*
It reports and never blocks; acting on the answer is a separate,
explicitly gated decision, because blocking is the only thing this
platform can do that locks an admin out of their own machine.
"""

from .service import ID_C2, ID_FLAGGED, ID_PAYLOAD, ThreatResult, ThreatService

__all__ = [
    "ThreatService", "ThreatResult",
    "ID_C2", "ID_PAYLOAD", "ID_FLAGGED",
]
