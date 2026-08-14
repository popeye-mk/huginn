"""The native assistant shell (A3 Phase 4+): registry, router, and — later —
server + config. Hosts the ops skills and routes questions to the grounded
answer path, so the platform can run without the vendored fork."""

from runtime.registry import SkillRegistry, auto_discover
from runtime.router import dispatch
from runtime.server import build_server

__all__ = ["SkillRegistry", "auto_discover", "dispatch", "build_server"]
