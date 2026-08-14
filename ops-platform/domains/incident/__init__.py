"""Incident domain (H2): freeze volatile evidence while it still exists."""

from domains.incident.service import build_snapshot, render_summary, save_snapshot

__all__ = ["build_snapshot", "render_summary", "save_snapshot"]
