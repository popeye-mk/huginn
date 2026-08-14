"""Matching observed connections against threat feeds.

**The v0.3 flagship claim, finally connected.** The design doc's central
example — *"high CPU plus an unknown outbound connection to a flagged IP
is one story, not two blips"* — needed two things the platform did not
have: something that sees outbound connections, and a feed of flagged
addresses. Both now exist. This introduces them.

## What a match is, and is not

A match says: **this machine opened a connection to an address that
somebody else's feed associates with something bad.** It does not say
the machine is compromised. Most of the distance between those two
statements is where security tools lose their users' trust, so the gap
is held open deliberately:

- **Confidence comes from the feed**, never from us. ThreatFox publishes
  0–100 per indicator; a 30 stays `possible` and a 100 becomes
  `certain`. Rounding everything up to "malicious" would manufacture
  certainty the source explicitly declined to claim.
- **A compromised legitimate host is labelled as one.** Blocking a
  hacked business site and blocking an attacker's server are different
  actions with different costs.
- **Only external peers are examined.** Matching an internet blocklist
  against `127.0.0.1` or the LAN is a category error, not a detection.

## Absence is never health, in the hardest place to hold the line

With no feed, or an empty one, this domain must report that it **checked
nothing** — not that it found nothing. A security check that reports
"clean" when it had no data to check against is worse than no check: it
converts ignorance into false assurance, and the operator stops looking.

So coverage counts connections *actually compared against a usable
feed*, and a stale feed carries its age into every finding it produces.
"""

from dataclasses import dataclass, field
from typing import List, Optional

from contracts import Connection, Coverage, Finding, Indicator
from storage.threat_feed import ThreatFeed, load_feeds

# Finding ids, keyed to what the feed says the threat is. Separate ids
# rather than one generic id because correlation rules match on ids, and
# "talking to a botnet controller" is a different story from "fetching a
# payload" — collapsing them would make both unaddressable.
ID_C2 = "threat_outbound_c2"
ID_PAYLOAD = "threat_outbound_payload"
ID_FLAGGED = "threat_outbound_flagged"

_THREAT_IDS = {
    "botnet_cc": ID_C2,
    "payload_delivery": ID_PAYLOAD,
}


@dataclass
class ThreatResult:
    """Matches, and an honest account of what was searchable."""

    findings: List[Finding] = field(default_factory=list)
    connections_examined: int = 0
    external_connections: int = 0
    feeds: List[str] = field(default_factory=list)
    unusable_feeds: List[str] = field(default_factory=list)
    machine_id: str = "unknown"

    @property
    def checked_anything(self) -> bool:
        """Whether the check was able to run at all.

        Deliberately about the **feeds**, not the connection count. A
        machine with no external connections has been checked properly
        and has nothing to report; a machine with no usable feed has not
        been checked at all. An earlier version conflated the two and
        told a perfectly healthy idle machine that its clean result was
        "NOT a clean bill of health" — technically defensible, and the
        kind of crying wolf that trains an operator to ignore the line
        that matters.
        """
        return bool(self.feeds)

    @property
    def had_nothing_to_check(self) -> bool:
        """Feeds were usable; this machine simply had no external peers."""
        return bool(self.feeds) and self.external_connections == 0

    @property
    def coverage(self) -> Coverage:
        """Connections compared against a usable feed, over those seen.

        `0/12 checked` when no feed is loaded — which reads as the
        warning it is, rather than as silence.
        """
        total = max(self.external_connections, 1)
        return Coverage(
            checked=self.connections_examined if self.feeds else 0,
            total=total,
        )

    @property
    def summary(self) -> str:
        if not self.feeds:
            reasons = "; ".join(self.unusable_feeds) or "no feeds configured"
            return (
                f"NOT CHECKED — {reasons}. "
                f"{self.external_connections} external connection(s) were "
                f"seen but compared against nothing."
            )
        if self.had_nothing_to_check:
            return (
                f"No external connections to check. {len(self.feeds)} feed(s) "
                f"were ready; this machine was not talking to the internet."
            )
        if not self.findings:
            return (
                f"{self.connections_examined} external connection(s) checked "
                f"against {len(self.feeds)} feed(s); no matches."
            )
        return (
            f"{len(self.findings)} connection(s) matched a threat feed."
        )


class ThreatService:
    """Compares connections to indicators. Reports; never blocks."""

    def __init__(self, feeds: Optional[List[ThreatFeed]] = None):
        self.feeds = feeds if feeds is not None else load_feeds()

    def usable_feeds(self) -> List[ThreatFeed]:
        return [f for f in self.feeds if f.status.is_usable]

    def match(
        self,
        connections: List[Connection],
        machine_id: str = "unknown",
    ) -> ThreatResult:
        """Check every external connection against every usable feed."""
        external = [c for c in connections if c.is_external]
        usable = self.usable_feeds()

        result = ThreatResult(
            external_connections=len(external),
            machine_id=machine_id,
            feeds=[f.name for f in usable],
            unusable_feeds=[
                f.status.summary for f in self.feeds if not f.status.is_usable
            ],
        )
        if not usable:
            return result

        for connection in external:
            result.connections_examined += 1
            finding = self._check(connection, usable, machine_id, len(external))
            if finding is not None:
                result.findings.append(finding)
        return result

    def _check(self, connection, feeds, machine_id, total) -> Optional[Finding]:
        for feed in feeds:
            indicator = feed.match_address(
                connection.remote_address, connection.remote_port
            )
            if indicator is not None:
                return self._finding(connection, indicator, feed, machine_id, total)
        return None

    def _finding(self, connection, indicator, feed, machine_id, total) -> Finding:
        """One match, stated at the strength the feed supports."""
        return Finding(
            id=_THREAT_IDS.get(indicator.threat_type, ID_FLAGGED),
            machine_id=machine_id,
            source_module="netdiag",
            severity=_severity(indicator),
            confidence=indicator.confidence,
            message=_message(connection, indicator),
            plain_message=_plain_message(connection, indicator),
            coverage=Coverage(checked=total, total=total),
            suggested_action=_action(connection, indicator, feed),
            # The feed is named in a tag as well as in the message.
            # Attribution is a licence condition for every feed this
            # platform reads, and a match nobody can trace back to a
            # source is a match nobody can check.
            tags=("security", f"feed:{feed.name}"),
        )


def _action(connection: Connection, indicator: Indicator, feed) -> str:
    """What to do — and deliberately not "block it".

    The platform's risk ceiling for R8 is detect and propose. Naming the
    process before touching the firewall is also just better advice: a
    blocked connection with no owner identified tells you nothing about
    how the machine got that way, and the malware simply picks another
    address.
    """
    age = feed.status.age_days
    caveat = (
        f" (feed is {age} days old — confirm the indicator is still current)"
        if age is not None and feed.status.is_stale else ""
    )
    if indicator.is_compromised:
        return (
            f"Identify the local process using {connection.peer} before "
            f"blocking anything: {indicator.value} is a compromised "
            f"legitimate host, so a block may break real work{caveat}."
        )
    return (
        f"Identify the local process holding {connection.peer} "
        f"(`ss -tunp` as root, or Resource Monitor), then isolate the "
        f"machine before restarting it — a restart loses the evidence{caveat}."
    )


def _severity(indicator: Indicator) -> str:
    """A live C2 conversation is critical; the rest is a warning.

    Severity comes from what the indicator *is*, while confidence comes
    from how sure the feed is. Keeping them separate means a low-
    confidence C2 match reads as "critical, but only possible" rather
    than being quietly demoted into the noise.
    """
    return "critical" if indicator.threat_type == "botnet_cc" else "warning"


def _message(connection: Connection, indicator: Indicator) -> str:
    return (
        f"Outbound connection to {connection.peer} matches "
        f"{indicator.description}"
    )


def _plain_message(connection: Connection, indicator: Indicator) -> str:
    """The version for someone who is not a security analyst."""
    what = indicator.malware or "known-bad infrastructure"
    if indicator.is_compromised:
        return (
            f"This machine connected to {connection.remote_address}, which is "
            f"a legitimate server that has been hacked and is being used to "
            f"host {what}. Blocking it may break something real — check what "
            f"on this machine was talking to it before acting."
        )
    return (
        f"This machine connected to {connection.remote_address}, an address "
        f"reported as {what}. That is a machine reaching out to somewhere it "
        f"should not — find the process responsible before it is restarted."
    )
