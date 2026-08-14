"""Diagnostic Companion engine wrapper.

Runs Diagnostic Companion's CLI and returns its JSON payload untouched.
Mapping to `Finding` happens in `domains/diagnostics/mapping.py` — see
`engines/base.py` for why that split exists.

Diagnostic Companion is never modified by this platform. This calls its
documented `--format json` interface and nothing else.
"""

import os
from pathlib import Path
from typing import Optional

from contracts.errors import EngineNotFoundError
from engines.base import DEFAULT_TIMEOUT, EngineOutput, run_command
from platform_support import python_executable


def _first_line(text: str) -> str:
    """The most useful line of a traceback: the last one.

    A missing-import failure ends with `ModuleNotFoundError: No module
    named 'yaml'`, which names the fix. The first line is just
    "Traceback (most recent call last):", which names nothing.
    """
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:200] if lines else ""

NAME = "diagnostic-companion"

# Bundled demo scenarios, useful for exercising the pipeline without
# needing a machine in a particular state.
DEMO_SCENARIOS = ("dying-disk", "dns-broken", "healthy", "smart-failing")

_DEFAULT_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "diagnostics"
    / "diagnostic-companion-v1.3"
    / "diagnostic-companion"
)


class DiagnosticCompanionEngine:
    """Wrapper over the `diag` CLI."""

    name = NAME

    def __init__(self, install_path: Optional[Path] = None):
        self.install_path = Path(
            install_path or os.environ.get("DC_PATH", _DEFAULT_PATH)
        )

    @property
    def cli_path(self) -> Path:
        return self.install_path / "cli.py"

    def is_available(self) -> bool:
        """Whether the CLI file is present.

        **Presence, not capability.** Kept cheap because callers use it on
        every run; `readiness()` is the honest answer and costs a
        subprocess.
        """
        return self.cli_path.is_file()

    def readiness(self, timeout: int = 60):
        """Actually run the tool and report whether it works.

        Added after the first real Windows run. `is_available()` returned
        True because `cli.py` was on disk, and then three checks failed
        with "output was not valid JSON" — the real cause being that
        Diagnostic Companion needs **PyYAML** (its knowledge base is
        YAML) and the machine did not have it.

        A file existing is not a tool working. That is the same mistake
        the ISO launcher made with the Windows `python3` stub, made twice
        in one codebase, so it is now a method rather than an assumption.

        Returns `(ok, reason)` — never raises, because a readiness probe
        that explodes has replaced the diagnosis with its own failure.
        """
        if not self.is_available():
            return False, f"not found at {self.cli_path}"
        try:
            out = run_command(
                engine=NAME,
                command=[python_executable(), "cli.py", "--help"],
                cwd=str(self.install_path),
                timeout=timeout,
                parse_json=False,
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {exc}"

        if out.exit_code != 0:
            return False, _first_line(out.stderr) or f"exit {out.exit_code}"
        return True, ""

    def run(
        self,
        demo: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> EngineOutput:
        """Collect diagnostics, or replay a demo scenario.

        Uses `python_executable()` rather than a literal "python3", which
        does not exist on a default Windows install.
        """
        if not self.is_available():
            raise EngineNotFoundError(
                NAME,
                "Diagnostic Companion not found",
                detail=f"looked for {self.cli_path}; set DC_PATH to override",
            )

        if demo is not None and demo not in DEMO_SCENARIOS:
            raise EngineNotFoundError(
                NAME,
                f"unknown demo scenario {demo!r}",
                detail=f"available: {', '.join(DEMO_SCENARIOS)}",
            )

        command = [python_executable(), "cli.py"]
        command += ["demo", demo] if demo else ["run"]
        command += ["--format", "json"]

        return run_command(
            engine=NAME,
            command=command,
            cwd=str(self.install_path),
            timeout=timeout,
            parse_json=True,
        )
