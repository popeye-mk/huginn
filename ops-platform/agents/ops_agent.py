"""Ops agent — routes IT-operations requests to domain services.

Implements the predecessor project's `AgentContract` (`can_handle` / `plan` / `execute` /
`explain`). Conforms to the predecessor project's existing agent model rather than
introducing a second one: the coordinator decides who runs, agents never
call each other.

**This agent contains routing and explanation, not business logic.** Any
calculation that appears here belongs in a domain service. That boundary
is what stops an agent from slowly becoming the god-file that
`anora.py` used to be.

Domains register into `_ROUTES` as they are built. Today that is
diagnostics; network, devices and backup join the same way, additively,
without this module growing a branch per domain.
"""

from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Callable, Dict, List, Optional

from agents import explaining, handlers, observing
from agents.routes import ROUTE_SPECS
from domains.backup import BackupService, VerificationRepository
from domains.correlation import CorrelationService
from domains.devices import DeviceRepository, DeviceService
from domains.diagnostics import DiagnosticsService
from domains.network import NetworkService
from domains.threat import ThreatService
from engines.connections import ConnectionsEngine
from storage import FindingsStore, KnowledgeBase

DEFAULT_STORE_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "findings" / "findings.json"
)
DEFAULT_DEVICES_DB = (
    Path(__file__).resolve().parent.parent / "data" / "devices" / "devices.db"
)
DEFAULT_VERIFICATIONS_DB = (
    Path(__file__).resolve().parent.parent / "data" / "backup" / "verifications.db"
)

AGENT_NAME = "ops_agent"
DOMAINS = ("ops", "diagnostics", "network", "security", "infrastructure")


@dataclass(frozen=True)
class Route:
    """One intent this agent can serve."""

    intent: str
    keywords: tuple
    handler: Callable
    description: str


class OpsAgent:
    """IT operations agent.

    Written to satisfy the predecessor project's `AgentContract` without importing it, so
    the ops platform stays testable standalone. The fork wires it to the
    real base class in R2; the method names and semantics already match.
    """

    name = AGENT_NAME

    def __init__(
        self,
        diagnostics: Optional[DiagnosticsService] = None,
        network: Optional[NetworkService] = None,
        correlation: Optional[CorrelationService] = None,
        store: Optional[FindingsStore] = None,
        devices: Optional[DeviceService] = None,
        threat: Optional[ThreatService] = None,
        backup: Optional[BackupService] = None,
        verifications: Optional[VerificationRepository] = None,
    ):
        self.diagnostics = diagnostics or DiagnosticsService()
        self.network = network or NetworkService()
        # Correlation gets the knowledge base so its stories can cite
        # what supports them. Built here rather than inside the service
        # so a test can hand it an empty one and check that ungrounded
        # stories still render — with their reason attached.
        self.correlation = correlation or CorrelationService(
            knowledge=KnowledgeBase()
        )
        # The store is the platform's memory of its own past. Injected so
        # tests can use a temporary file rather than accumulating history
        # into the real one.
        self.store = store if store is not None else FindingsStore(DEFAULT_STORE_PATH)
        self.devices = devices if devices is not None else DeviceService(
            DeviceRepository(DEFAULT_DEVICES_DB)
        )
        self.threat = threat if threat is not None else ThreatService()
        self.connections_engine = ConnectionsEngine()
        self.backup = backup if backup is not None else BackupService()
        self.verifications = (
            verifications if verifications is not None
            else VerificationRepository(DEFAULT_VERIFICATIONS_DB)
        )
        self._routes = self._build_routes()

    def _build_routes(self) -> List[Route]:
        """Bind each declared intent to its handler.

        The table itself lives in `routes.py` as data; this only wires
        handlers to it, so adding a verb is a row there plus a method
        here.
        """
        bound = {
            "history": partial(handlers.history, self),
            "threat": partial(handlers.threat, self),
            "backup": partial(handlers.backup, self),
            "devices": partial(handlers.devices, self),
            "triage": partial(handlers.triage, self),
            "security": partial(handlers.security, self),
            "netcheck": partial(handlers.netcheck, self),
            "diagnose": partial(handlers.diagnose, self),
        }
        return [
            Route(spec.intent, spec.keywords, bound[spec.intent], spec.description)
            for spec in ROUTE_SPECS
            if spec.intent in bound
        ]

    # -- AgentContract surface ------------------------------------------

    def can_handle(self, text: str) -> bool:
        """Fast gate: does any route claim this text?"""
        return self._match(text) is not None

    def plan(self, text: str) -> Dict[str, object]:
        """Which route would run, and is its engine actually available.

        Availability is part of the plan rather than discovered mid-run,
        so a missing tool is reported as "cannot check" instead of
        surfacing as an error that looks like a fault on the machine.
        """
        route = self._match(text)
        if route is None:
            return {"intent": None, "available": False}
        return {
            "intent": route.intent,
            "available": self._availability(route.intent),
            "description": route.description,
        }

    # -- direct intent entry points --------------------------------------
    #
    # Skills already know which verb they are; they must not re-route
    # through `execute`. the predecessor project's registry strips the skill name before
    # calling, so `diagnose the disk` arrives as args="the disk" — which
    # matches no keyword and produced "No ops action matched that
    # request." These methods take the remaining text as a *query*
    # rather than as routing input.

    def diagnose(self) -> Dict[str, object]:
        return handlers.diagnose(self)

    def netcheck(self) -> Dict[str, object]:
        return handlers.netcheck(self)

    def security(self) -> Dict[str, object]:
        return handlers.security(self)

    def triage(self) -> Dict[str, object]:
        return handlers.triage(self)

    def history(self, query: str = "") -> Dict[str, object]:
        return handlers.history(self, query)

    def devices_view(self) -> Dict[str, object]:
        return handlers.devices(self)

    def threat_check(self) -> Dict[str, object]:
        return handlers.threat(self)

    def backup_check(self, boot_test: bool = False) -> Dict[str, object]:
        return handlers.backup(self, boot_test=boot_test)

    def execute(self, text: str) -> Dict[str, object]:
        """Route free text to a verb. Used when the intent is unknown."""
        route = self._match(text)
        if route is None:
            return {
                "ok": False,
                "body": "No ops action matched that request.",
                "findings": [],
            }
        return route.handler(text)

    def explain(self, result: Dict[str, object]) -> str:
        """Plain-language summary. The wording lives in `explaining`."""
        return explaining.explain(result)

    # -- routing ---------------------------------------------------------

    def _match(self, text: str) -> Optional[Route]:
        lowered = (text or "").strip().lower()
        if not lowered:
            return None
        for route in self._routes:
            if any(keyword in lowered for keyword in route.keywords):
                return route
        return None

    def _availability(self, intent: str) -> bool:
        if intent == "diagnose":
            return self.diagnostics.is_available()
        if intent in ("netcheck", "security"):
            return self.network.is_available()
        if intent == "threat":
            # Feeds are files, so this works offline. What it cannot do
            # is check against feeds nobody downloaded — reported as
            # coverage rather than as unavailability, because the check
            # itself ran fine.
            return self.connections_engine.is_available()
        if intent == "backup":
            return self.backup.is_available()
        if intent in ("history", "devices"):
            return True   # reading stored state needs no engine
        if intent == "triage":
            # Triage runs with whatever is present, but says which engines
            # contributed — a correlation report from one engine has not
            # tested for cross-signal stories at all.
            return self.diagnostics.is_available() or self.network.is_available()
        return False
    # -- observation ------------------------------------------------------

    def observed_connections(self):
        """This machine's current connections, parsed for this OS."""
        return observing.observe(self.connections_engine)

