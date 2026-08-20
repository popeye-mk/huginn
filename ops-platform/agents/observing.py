"""Observing this machine's connections, for whoever asks.

Split out of `ops_agent` when adding the `threat` verb pushed it past
the 400-line limit — the third time that rule has forced a genuine
separation rather than a cosmetic one. What moved is *observation*:
running the connections engine and turning its output into contracts.
What stayed is routing.

The split has a second benefit that justifies it beyond line count. Both
the `threat` verb and `triage` need the same observation, and before
this they would have needed either a shared private method on the agent
or two call sites drifting apart. Now there is one function, and the
parser choice — different on Linux and Windows — lives beside it rather
than inside a router.
"""

from typing import Callable, List

from contracts import Connection
from domains.network.connections import parse_linux, parse_macos, parse_windows
from engines.connections import ConnectionsEngine
from platform_support import connection_format


def observe(engine: ConnectionsEngine) -> List[Connection]:
    """List this machine's connections and parse them for this OS.

    Which parser to use comes from `platform_support`, never from an
    `if windows` here: `ss` emits whitespace columns, macOS `netstat`
    emits BSD columns, and PowerShell emits JSON objects. Asking the
    parser to sniff which one it got would make a malformed response
    indistinguishable from a foreign format — and the "not JSON, so Linux"
    fall-through this replaces silently mis-parsed every macOS row until a
    real Mac run.
    """
    output = engine.run()
    fmt = connection_format()
    if fmt == "json":
        return parse_windows(output.payload)
    if fmt == "bsd":
        return parse_macos(output.payload)
    return parse_linux(output.payload)


def observer(engine: ConnectionsEngine) -> Callable[[], List[Connection]]:
    """A no-argument callable that observes when invoked.

    `gather.collect` takes this rather than a list so that connections
    are listed only when a threat check is actually going to happen —
    running `ss` during a triage that has no feeds to compare against
    would be work nobody asked for.
    """
    return lambda: observe(engine)


def threat_report(threat_service, engine, machine_id: str, store=None) -> dict:
    """Observe connections and compare them to threat feeds.

    Lives here rather than in the agent because it is observation plus
    one domain call, and the agent layer is meant to hold routing and
    explanation only. Keeping it out is what stopped `ops_agent` from
    crossing the god-file limit for the third time.

    Failure is returned, never raised: a machine whose connection list
    cannot be read still deserves the rest of its diagnostics.

    When a findings store is passed, recall is attached here (P1) — the
    same memory layer triage uses. A clean check has no finding, so recall
    stays silent; a match volunteers past occurrences and course notes.
    """
    try:
        connections = observe(engine)
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "body": f"Could not list connections: {type(exc).__name__}: {exc}",
            "findings": [],
        }

    result = threat_service.match(connections, machine_id=machine_id)
    report = {
        "ok": True,
        "intent": "threat",
        "findings": result.findings,
        "threat": result,
        "machine_id": machine_id,
        # Coverage travels with the result. A threat check that found
        # nothing because no feed was loaded must never read the same as
        # one that found nothing after checking properly.
        "not_checked": [] if result.checked_anything else [
            ("threat-feeds", result.summary)
        ],
    }
    if store is not None:
        from agents import recalling  # local: recall is an optional rider
        recalling.attach_recall(report, store)
    return report
