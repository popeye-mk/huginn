"""netdiag engine wrapper.

netdiag ships one static binary per OS, so binary selection goes through
`platform_support.resolve_binary` rather than a local `if windows` — the
rule that keeps OS knowledge in one module.

Only passive verbs are exposed here. netdiag gates its active network
sweep behind `-authorized` plus a typed confirmation, and this wrapper
deliberately provides no way to pass that flag: an automated platform
should not be able to start scanning other people's machines because a
config value flipped. If that capability is ever wanted, it belongs
behind an explicit, separately-reviewed entry point.
"""

from pathlib import Path
from typing import Optional

from engines.base import DEFAULT_TIMEOUT, EngineOutput, run_command
from platform_support import resolve_binary

NAME = "netdiag"

# Symptom walks netdiag supports. These mirror how tickets actually
# arrive ("I can't log in") rather than how networks are structured.
SYMPTOMS = (
    "no-internet", "slow", "wifi", "intermittent",
    "cant-reach", "cant-print", "cant-rdp", "cant-login",
)

_DEFAULT_DIR = (
    Path(__file__).resolve().parent.parent.parent / "network" / "netdiag_v1"
)


class NetdiagEngine:
    """Wrapper over the netdiag binary."""

    name = NAME

    def __init__(self, install_dir: Optional[Path] = None):
        self.install_dir = Path(install_dir or _DEFAULT_DIR)

    def _binary(self) -> Path:
        return resolve_binary(NAME, search_dirs=(self.install_dir,))

    def is_available(self) -> bool:
        try:
            self._binary()
            return True
        except Exception:
            return False

    def run(self, timeout: int = DEFAULT_TIMEOUT) -> EngineOutput:
        """Passive scan: snapshot, findings and blame verdict as JSON."""
        return run_command(
            engine=NAME,
            command=[str(self._binary()), "-json"],
            timeout=timeout,
            parse_json=True,
        )

    def why(
        self,
        symptom: str,
        target: str = "",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> EngineOutput:
        """Symptom-driven layer walk — netdiag's `why` verb."""
        if symptom not in SYMPTOMS:
            from contracts.errors import EngineNotFoundError
            raise EngineNotFoundError(
                NAME,
                f"unknown symptom {symptom!r}",
                detail=f"available: {', '.join(SYMPTOMS)}",
            )

        command = [str(self._binary()), "why", symptom]
        if target:
            command.append(target)
        command.append("-json")

        return run_command(
            engine=NAME, command=command, timeout=timeout, parse_json=True
        )
