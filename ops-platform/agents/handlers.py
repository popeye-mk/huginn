"""Ops request handlers — how each verb shapes its response.

Extracted from `ops_agent` (Stage C) so the agent stays what its own
docstring promises: routing, wiring and the contract surface. Each handler
is a free function taking the already-constructed `agent` and returning the
result dict its verb produces. **No business logic lives here either** — a
handler calls a domain service on the agent and shapes the answer (attaching
recall where a finding warrants it); the calculation stays in the domain.

Kept as free functions rather than methods so the split is real: nothing
here can reach agent state except through the `agent` handed in, and the
route table binds them with `functools.partial(handler, agent)`.
"""

from platform_support import hostname
from agents import gather, observing, recalling, recording
from storage import recall


def diagnose(agent, text: str = "") -> dict:
    del text  # routing already consumed it; no args parsed yet
    if not agent.diagnostics.is_available():
        return {
            "ok": False,
            "body": "Diagnostic Companion is not available on this machine.",
            "findings": [],
        }
    result = agent.diagnostics.run()
    return {
        "ok": True,
        "intent": "diagnose",
        "findings": result.findings,
        "headline": result.headline,
        "health_score": result.health_score,
        "not_checked": result.not_checked,
        "machine_id": result.machine_id,
    }


def netcheck(agent, text: str = "") -> dict:
    del text
    if not agent.network.is_available():
        return {
            "ok": False,
            "body": "netdiag is not available on this machine.",
            "findings": [],
        }
    result = agent.network.run()
    return recalling.attach_recall({
        "ok": True,
        "intent": "netcheck",
        "findings": result.findings,
        "headline": result.verdict,
        "not_checked": result.not_checked,
        "unknown_segments": result.unknown_segments,
        "machine_id": result.machine_id,
    }, agent.store)


def triage(agent, text: str = "") -> dict:
    """Run every available engine and correlate across them.

    This is the platform's distinguishing behaviour: one machine, several
    sensors, one story.
    """
    del text
    gathered = gather.collect(
        agent.diagnostics, agent.network,
        threat=agent.threat, connections=agent.observed_connections,
    )
    if not gathered.any_engine_ran:
        return {
            "ok": False,
            "body": "No diagnostic engines are available on this machine.",
            "findings": [],
        }
    result = agent.correlation.correlate(
        gathered.findings, machine_id=gathered.machine_id
    )
    report, record_error = recording.persist_triage(
        agent.store, agent.devices, gathered, result
    )
    return recalling.attach_recall({
        "ok": True,
        "intent": "triage",
        "findings": result.findings,
        "correlations": result.correlations,
        "standalone": result.standalone_findings,
        "suppressed_ids": result.suppressed_ids,
        "engines_run": gathered.engines_run,
        "engines_missing": gathered.engines_missing,
        "threat_summary": gathered.threat_summary,
        "not_checked": gathered.not_checked,
        "machine_id": gathered.machine_id,
        "recorded": report,
        "record_error": record_error,
    }, agent.store)


def devices(agent, text: str = "") -> dict:
    """Every machine this platform knows about."""
    del text
    return {
        "ok": True,
        "intent": "devices",
        "findings": [],
        "fleet": agent.devices.fleet(),
    }


def threat(agent, text: str = "") -> dict:
    """Compare outbound connections against threat feeds.

    Recall rides along (P1) via the store passed here: a threat match carries
    a finding, so memory can volunteer history + course notes.
    """
    del text
    return observing.threat_report(
        agent.threat, agent.connections_engine, hostname(), store=agent.store
    )


def backup(agent, text: str = "", boot_test: bool = False) -> dict:
    """Verify a backup, and keep the result whatever it says.

    The verification is recorded before it is returned, including failures
    and NOT_ATTEMPTED. A history that only kept successes would answer "has
    this ever worked" and never "when did it stop" — and the second question
    is the one asked after an incident.
    """
    del text
    machine = hostname()
    verification = agent.backup.verify(machine, host=machine, boot_test=boot_test)
    return {
        "ok": True,
        "intent": "backup",
        "findings": [],
        "verification": verification,
        "record_error": recording.persist_verification(
            agent.verifications, verification
        ),
        "previous": recording.verification_history(
            agent.verifications, machine
        ),
    }


def history(agent, text: str = "") -> dict:
    """Recall what has been seen on this machine before."""
    result = recall(agent.store, text or "", top_k=5)
    return {
        "ok": True,
        "intent": "history",
        "findings": [],
        "recall": result,
        "recurring": agent.store.recurring(),
    }


def security(agent, text: str = "") -> dict:
    """Security exposure only — a deliberately narrower answer.

    Returning the full network scan here would bury four exposure findings
    under a dozen connectivity ones. Someone asking about security is asking
    a different question.
    """
    del text
    if not agent.network.is_available():
        return {
            "ok": False,
            "body": "netdiag is not available on this machine.",
            "findings": [],
        }
    result = agent.network.run()
    return recalling.attach_recall({
        "ok": True,
        "intent": "security",
        "findings": result.security_findings,
        "headline": "",
        "not_checked": result.not_checked,
        "machine_id": result.machine_id,
    }, agent.store)
