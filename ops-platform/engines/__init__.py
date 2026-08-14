"""External tool wrappers. Every subprocess call in the codebase is here.

Engines return raw `EngineOutput`. Mapping to contracts is the domain
layer's job — see `engines/base.py` for the reasoning.
"""

from .base import DEFAULT_TIMEOUT, Engine, EngineOutput, run_command
from .connections import ConnectionsEngine
from .diagnostic_companion import DiagnosticCompanionEngine
from .netdiag import NetdiagEngine
from .restic import ResticEngine
from .sandbox_base import (
    ConsoleLog,
    Sandbox,
    SandboxResult,
    create_sandbox,
    register_sandbox,
)

__all__ = [
    "Engine", "EngineOutput", "run_command", "DEFAULT_TIMEOUT",
    "DiagnosticCompanionEngine", "NetdiagEngine", "ResticEngine",
    "ConnectionsEngine",
    "Sandbox", "SandboxResult", "ConsoleLog",
    "create_sandbox", "register_sandbox",
]
