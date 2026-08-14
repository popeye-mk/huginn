"""CommandResult — the envelope a skill returns to the assistant shell.

A2/A3: this is the first native primitive of the lean assistant (A3 Phase 1).
The vendored fork defines the same two-field shape in
`anora_core.knowledge.web`; the ops bridge used to reach in for it, which made
the fork's answer module a dependency of every ops skill result. Defining it
here — a pure dataclass, no logic — lets the bridge import it from the
platform instead, shrinking the ops→fork surface. It is duck-typed everywhere
(the fork does zero isinstance checks on it), so the two definitions
interoperate during the migration.
"""

from dataclasses import dataclass


@dataclass
class CommandResult:
    """Whether a command succeeded, and the text to show for it."""

    ok: bool
    message: str = ""
