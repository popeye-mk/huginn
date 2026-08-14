"""Connections engine — what this machine is actually talking to.

The missing input. Every threat-feed idea in the R8 design assumed the
platform could see outbound connections; nothing could. netdiag reports
`sockets_established = 3` — a count, with no peers — and Diagnostic
Companion does not look at the network at all.

**This engine only observes.** It returns raw output; deciding what a
peer *means* is the domain layer's job, as with every other engine here.
That split matters more than usual for this one, because the temptation
to write "unknown remote address = suspicious" directly into a collector
is exactly how a security tool starts crying wolf.

**No elevation required.** On Linux `ss -p` would name the owning
process but needs root for other users' sockets; it is deliberately not
requested. A read-only question that demands root is a question that
gets asked less often, and the answer here is useful without it.
"""

from typing import Optional

from engines.base import DEFAULT_TIMEOUT, EngineOutput, run_command
from platform_support.commands import connection_command, connection_output_is_json

NAME = "connections"

# Listing sockets is fast everywhere. A long timeout here would only
# ever mean something is badly wrong, and waiting three minutes to find
# that out helps nobody.
LIST_TIMEOUT = 30


class ConnectionsEngine:
    """Lists established network connections on this machine."""

    name = NAME

    def __init__(self, command: Optional[list] = None):
        # Injectable so tests can exercise the real parser against
        # captured output from the *other* operating system, which is
        # otherwise impossible to reach.
        self._command = command

    def command(self) -> list:
        return list(self._command) if self._command else connection_command()

    def is_available(self) -> bool:
        """Whether the listing tool answers on this machine.

        Runs it rather than checking for the binary. `is_available()`
        returning True for a tool that cannot run has cost this project
        a round trip three times now — the Windows `python3` stub, the
        Diagnostic Companion CLI without PyYAML, and each time the
        lesson was the same: presence is not capability.
        """
        try:
            return self.run(timeout=15).exit_code == 0
        except Exception:  # noqa: BLE001
            return False

    def run(self, timeout: int = LIST_TIMEOUT) -> EngineOutput:
        """List connections. Raw output; the domain decides what it means."""
        return run_command(
            engine=NAME,
            command=self.command(),
            timeout=timeout or DEFAULT_TIMEOUT,
            parse_json=connection_output_is_json(),
        )
