"""Check this machine's real connections against the downloaded feeds.

    python3 tools/update_feeds.py       # first: get the feeds
    python3 tools/check_threat_live.py  # then: check this machine

The first honest end-to-end run of R8: real `ss` output, real ThreatFox
indicators, real verdict. Read-only — it observes and reports, and
blocks nothing.

**A clean result here is the expected result.** If this machine were
talking to a botnet controller that would be a genuine emergency, so
"0 matches" is good news, not a failed test. What is actually being
proven is that the pipeline ran end to end and that the coverage line
tells the truth about what was compared.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.observing import observe  # noqa: E402
from domains.threat import ThreatService  # noqa: E402
from engines.connections import ConnectionsEngine  # noqa: E402
from platform_support import hostname  # noqa: E402
from storage.threat_feed import load_feeds  # noqa: E402


def _connections():
    """Observe what this machine is talking to, right now.

    Delegates to `agents.observing.observe` rather than choosing the parser
    itself — that choice used to be copied here, and the copy silently
    mis-parsed macOS after the real one was fixed. One source of truth now.
    """
    return observe(ConnectionsEngine())


def _print_feeds(feeds) -> None:
    print("  Feeds")
    print("  " + "-" * 66)
    if not feeds:
        print("   none found in data/feeds/ — run tools/update_feeds.py first")
    for feed in feeds:
        print(f"   {feed.status.summary}")
    print()


def _print_connections(connections) -> None:
    external = [c for c in connections if c.is_external]
    print("  Connections")
    print("  " + "-" * 66)
    print(f"   {len(connections)} total, {len(external)} external")
    for connection in external[:12]:
        print(f"     {connection.protocol:4} {connection.peer:46} {connection.state}")
    if len(external) > 12:
        print(f"     ... and {len(external) - 12} more")
    print()


def _print_result(result) -> None:
    print("  Result")
    print("  " + "-" * 66)
    print(f"   coverage  {result.coverage}")
    print(f"   {result.summary}")
    print()

    for finding in result.findings:
        print(f"   [{finding.severity}/{finding.confidence}] {finding.id}")
        print(f"     {finding.message}")
        print(f"     -> {finding.suggested_action}")
        print()


def main() -> int:
    print(f"\n  R8 live threat check — {hostname()}")
    print("  " + "=" * 66 + "\n")

    feeds = load_feeds()
    _print_feeds(feeds)

    try:
        connections = _connections()
    except Exception as exc:  # noqa: BLE001
        print(f"  could not list connections: {type(exc).__name__}: {exc}")
        return 2
    _print_connections(connections)

    result = ThreatService(feeds=feeds).match(connections, machine_id=hostname())
    _print_result(result)

    print("  " + "=" * 66)
    if not result.checked_anything:
        # The distinction the whole domain exists to preserve.
        print("  NOT CHECKED. This is not a clean bill of health — nothing")
        print("  was compared. Run tools/update_feeds.py.")
        return 1
    if result.findings:
        print("  Matches found. Identify the owning process before acting;")
        print("  a restart destroys the evidence.")
        return 1
    print("  Checked and clean — and the coverage line above says exactly")
    print("  how much was checked, which is the part that matters.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
