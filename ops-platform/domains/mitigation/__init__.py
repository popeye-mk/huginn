"""Mitigation domain (G6): recommend fixes for the human to run. Never acts."""

from domains.mitigation.service import (
    Mitigation, mitigation_for, mitigations_for,
)

__all__ = ["Mitigation", "mitigation_for", "mitigations_for"]
