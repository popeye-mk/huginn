"""AI layer. Agents implement the predecessor project's AgentContract.

Agents route and explain; they never contain business logic, and they
never call each other — the coordinator decides who runs.
"""

from .ops_agent import OpsAgent

__all__ = ["OpsAgent"]
