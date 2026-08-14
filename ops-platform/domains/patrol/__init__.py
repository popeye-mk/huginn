"""Patrol domain (G4): decide when the guard loop should alert."""

from domains.patrol.service import (
    PatrolResult,
    alert_event,
    escalations,
    evaluate,
)

__all__ = ["PatrolResult", "alert_event", "escalations", "evaluate"]
