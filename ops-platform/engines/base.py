"""Engine protocol — the contract every external-tool wrapper implements.

**This layer holds every `subprocess` call in the codebase.** That is
enforced by the architecture test, not by convention. The reason is
testability: domains that shell out cannot be tested without the tool
installed, so domains that never shell out stay testable everywhere.

Engines are deliberately dumb. They run a tool and hand back its raw
payload with some metadata. They do **not** produce `Finding` objects,
because turning tool output into findings is a decision — which fields
matter, what maps to which severity — and decisions belong in domains
where they can be changed without touching process handling.
"""

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol

from contracts.errors import (
    EngineNotFoundError,
    EngineOutputError,
    EngineTimeoutError,
)

DEFAULT_TIMEOUT = 180


@dataclass
class EngineOutput:
    """What an engine returns: raw payload plus how it was obtained.

    `exit_code` is retained rather than collapsed into success/failure
    because these tools use it meaningfully — Diagnostic Companion exits
    2 for critical findings, which is the tool working correctly, not
    failing. An engine that treated non-zero as an error would report a
    dying disk as a broken engine.
    """

    engine: str
    payload: Any
    exit_code: int = 0
    stderr: str = ""
    duration_ms: float = 0.0
    collected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    command: List[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return self.payload is None or self.payload == {}


class Engine(Protocol):
    """What every engine wrapper provides."""

    name: str

    def is_available(self) -> bool:
        """Whether this tool can be run right now."""
        ...

    def run(self, **kwargs) -> EngineOutput:
        """Execute the tool and return its raw output."""
        ...


def _execute(engine, command, cwd, timeout, env):
    """Run the process, translating failures into typed engine errors."""
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        raise EngineNotFoundError(
            engine, f"executable not found: {command[0]}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise EngineTimeoutError(
            engine, f"timed out after {timeout}s",
            detail=" ".join(str(c) for c in command),
        ) from exc


def _parse_payload(engine, proc, parse_json):
    """Decode stdout, raising a typed error if JSON was expected but absent."""
    if not parse_json:
        return proc.stdout
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        detail = (proc.stderr or proc.stdout or "").strip()[:400]
        raise EngineOutputError(
            engine, "output was not valid JSON", detail=detail
        ) from exc


def run_command(
    engine: str,
    command: List[str],
    cwd: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    parse_json: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> EngineOutput:
    """Run an external tool and capture its output.

    Shared by every engine so process handling, timeouts and error
    translation exist once. Deliberately never uses `shell=True`:
    argument lists behave identically on Windows and Linux, while shell
    strings do not, and quoting differences are a classic source of
    "works on my OS" bugs.
    """
    started = datetime.now(timezone.utc)
    proc = _execute(engine, command, cwd, timeout, env)
    duration_ms = (
        datetime.now(timezone.utc) - started
    ).total_seconds() * 1000.0

    return EngineOutput(
        engine=engine,
        payload=_parse_payload(engine, proc, parse_json),
        exit_code=proc.returncode,
        stderr=proc.stderr or "",
        duration_ms=duration_ms,
        command=[str(c) for c in command],
    )
