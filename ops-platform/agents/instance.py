"""The shared ops agent.

Each skill module used to create its own `OpsAgent()`. Four skills meant
four agents, four findings stores over the same file, and state that
could not be shared — attaching the embedder to one left the other three
falling back to substring recall. Nothing errored; recall was just
quietly worse in three places out of four.

One instance fixes all of it: configuration applied once applies
everywhere, and the store is loaded once rather than four times.

`configure()` exists so the fork can inject the embedder after import,
and so tests can substitute a temporary store instead of accumulating
history into the real one.
"""

from typing import Callable, Optional

from agents.ops_agent import OpsAgent

_agent: Optional[OpsAgent] = None


def get_agent() -> OpsAgent:
    """The shared agent, created on first use."""
    global _agent
    if _agent is None:
        _agent = OpsAgent()
    return _agent


def configure(
    embedder: Optional[Callable] = None,
    store=None,
) -> OpsAgent:
    """Adjust the shared agent in place.

    Returns it so callers can chain. Replacing the whole agent is
    deliberately not offered: skills hold no reference of their own, and
    swapping the object underneath them would reintroduce exactly the
    split-state problem this module exists to remove.
    """
    agent = get_agent()
    if store is not None:
        agent.store = store
    if embedder is not None:
        agent.store.embedder = embedder
    return agent


def reset() -> None:
    """Drop the shared agent. For tests only."""
    global _agent
    _agent = None
