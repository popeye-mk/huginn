"""`adopt` skill — take over a data directory that belongs to another machine.

    adopt          transfer ownership of this data/ to this machine

The documented way past the ownership guard in `agents/owning.py`, and the
only verb that guard lets through. It is a verb rather than a flag because
the consequence needs explaining and a flag explains nothing: ownership is a
lock, not a repair, and the baselines inside were built by a different
machine's view of the network.

Nobody runs this by accident. Anyone who runs it has just read a refusal
that named it.
"""

from typing import Any

from agents.owning import adopt as adopt_directory
from platform_support import hostname


def skill_adopt(args: str, speaker: Any = None) -> str:
    """Claim this data directory for this machine."""
    del args, speaker
    return adopt_directory(hostname())


def register(registry) -> None:
    registry.register(
        "adopt",
        skill_adopt,
        aliases=[
            "take ownership", "claim data", "adopt data directory",
            "eigenaar worden",                             # NL
            "adopter",                                     # FR
        ],
    )
