"""Matching connections against feeds — the v0.3 flagship claim (R8).

Two halves that existed separately are introduced here: observed
outbound connections, and indicators from a threat feed.

**The tests are almost entirely about restraint.** Matching is easy; the
hard part is not overclaiming. A match means *this machine opened a
connection to an address somebody else's feed associates with something
bad* — not that the machine is compromised. Every test below defends
some part of that gap:

- confidence comes from the feed, never from us
- a compromised legitimate host is labelled, because blocking it costs
  something a malicious host does not
- loopback and LAN peers are never matched against an internet blocklist
- **no feed means "not checked", never "clean"**

That last one is the whole reason this file is long. A security check
that reports clean when it had nothing to check against converts
ignorance into assurance, and the operator stops looking.

Run: python3 tools/test_threat_match.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import Connection  # noqa: E402
from domains.threat import ID_C2, ID_PAYLOAD, ThreatService  # noqa: E402
from storage.threat_feed import ThreatFeed  # noqa: E402

HEADER = (
    "# ThreatFox IOCs\n"
    "# Last updated: {stamp} UTC\n"
    "#\n"
)

# Real row shapes from the live export.
C2_ROW = (
    '"2026-07-21 05:35:20", "1854731", "157.20.182.81:425", "ip:port", '
    '"botnet_cc", "win.tofsee", "Gheg", "Tofsee", "", "75", "False", "", '
    '"Tofsee", "0", "abuse_ch"\n'
)
PAYLOAD_ROW = (
    '"2026-07-21 05:20:00", "1854588", "198.51.100.7:8080", "ip:port", '
    '"payload_delivery", "win.example", "None", "ExampleLoader", "", "100", '
    '"False", "", "Example", "0", "tester"\n'
)
COMPROMISED_ROW = (
    '"2026-07-21 05:19:00", "1854587", "203.0.113.44:443", "ip:port", '
    '"botnet_cc", "win.other", "None", "OtherBot", "", "30", "True", "", '
    '"Other", "0", "tester"\n'
)


def _feed(rows=C2_ROW + PAYLOAD_ROW + COMPROMISED_ROW, days_old=0):
    stamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    path = Path(tempfile.mkdtemp()) / "threatfox.csv"
    path.write_text(HEADER.format(stamp=stamp) + rows, encoding="utf-8")
    return ThreatFeed(path)


def _connection(remote, port=443):
    return Connection(
        protocol="tcp", local_address="192.168.1.10", local_port=50000,
        remote_address=remote, remote_port=port, state="ESTABLISHED",
    )


# --- the flagship: a match happens ----------------------------------------

def test_a_connection_to_a_flagged_address_is_found():
    result = ThreatService(feeds=[_feed()]).match(
        [_connection("157.20.182.81", 425)], "web-02"
    )
    assert len(result.findings) == 1
    assert result.findings[0].id == ID_C2
    assert "157.20.182.81" in result.findings[0].message


def test_the_finding_is_tagged_security_and_names_its_feed():
    """Attribution is a licence condition and a checkability requirement."""
    finding = ThreatService(feeds=[_feed()]).match(
        [_connection("157.20.182.81", 425)]
    ).findings[0]
    assert "security" in finding.tags
    assert any(t.startswith("feed:") for t in finding.tags)


def test_threat_type_selects_the_finding_id():
    """C2 and payload delivery are different stories, so different ids.

    Correlation rules match on ids; collapsing both into one would make
    neither addressable.
    """
    service = ThreatService(feeds=[_feed()])
    assert service.match([_connection("157.20.182.81", 425)]).findings[0].id == ID_C2
    assert service.match([_connection("198.51.100.7", 8080)]).findings[0].id == ID_PAYLOAD


# --- restraint ------------------------------------------------------------

def test_confidence_comes_from_the_feed_not_from_us():
    """75 -> likely, 100 -> certain, 30 -> possible. Never rounded up."""
    service = ThreatService(feeds=[_feed()])
    assert service.match([_connection("157.20.182.81", 425)]).findings[0].confidence == "likely"
    assert service.match([_connection("198.51.100.7", 8080)]).findings[0].confidence == "certain"
    assert service.match([_connection("203.0.113.44", 443)]).findings[0].confidence == "possible"


def test_a_low_confidence_c2_stays_critical_but_only_possible():
    """Severity and confidence are separate axes.

    A C2 match is critical because of what it would mean; the feed's
    30% is why it is only `possible`. Demoting the severity to match
    the confidence would bury it in the noise.
    """
    finding = ThreatService(feeds=[_feed()]).match(
        [_connection("203.0.113.44", 443)]
    ).findings[0]
    assert finding.severity == "critical"
    assert finding.confidence == "possible"


def test_a_compromised_host_changes_the_advice_not_just_a_flag():
    """Blocking a hacked business site costs something. Say so.

    Note the two registers: the technical action says "compromised
    legitimate host", the plain-language line says "hacked". That is
    deliberate — `plain_message` exists for the person who is not a
    security analyst, and "compromised" is jargon to them.
    """
    finding = ThreatService(feeds=[_feed()]).match(
        [_connection("203.0.113.44", 443)]
    ).findings[0]

    plain = finding.for_display().lower()
    assert "hacked" in plain
    assert "may break something real" in plain
    assert "compromised legitimate host" in finding.suggested_action


def test_the_advice_never_says_block_it_first():
    """R8's risk ceiling, enforced in the text the operator reads.

    A blocked connection with no process identified explains nothing
    about how the machine got that way, and the implant picks another
    address.
    """
    finding = ThreatService(feeds=[_feed()]).match(
        [_connection("157.20.182.81", 425)]
    ).findings[0]
    assert "identify the local process" in finding.suggested_action.lower()


def test_a_stale_feed_puts_its_age_in_the_advice():
    finding = ThreatService(feeds=[_feed(days_old=200)]).match(
        [_connection("157.20.182.81", 425)]
    ).findings[0]
    assert "days old" in finding.suggested_action


# --- what is never matched ------------------------------------------------

def test_loopback_and_lan_peers_are_not_matched():
    """An internet blocklist against 127.0.0.1 is a category error."""
    result = ThreatService(feeds=[_feed()]).match([
        _connection("127.0.0.1", 6379),
        _connection("192.168.1.50", 445),
        _connection("10.0.0.8", 22),
    ])
    assert result.findings == []
    assert result.external_connections == 0


def test_an_unlisted_external_peer_produces_nothing():
    result = ThreatService(feeds=[_feed()]).match([_connection("93.184.216.34", 443)])
    assert result.findings == []
    assert result.connections_examined == 1


def test_the_port_matters_when_the_feed_published_one():
    """`157.20.182.81:425` was observed on port 425.

    A different port on the same address is a weaker claim, and the
    address-level fallback is what makes it still visible rather than
    silently dropped.
    """
    service = ThreatService(feeds=[_feed()])
    exact = service.match([_connection("157.20.182.81", 425)]).findings
    other = service.match([_connection("157.20.182.81", 9999)]).findings
    assert exact and other        # both reported
    assert exact[0].id == ID_C2


# --- absence is never health ----------------------------------------------

def test_no_feed_means_not_checked_not_clean():
    """The most important test in this file.

    With no feed there are no findings — and a naive reader would call
    that clean. Coverage must say otherwise.
    """
    result = ThreatService(feeds=[]).match([_connection("157.20.182.81", 425)])
    assert result.findings == []
    assert result.checked_anything is False
    assert result.coverage.checked == 0
    assert "NOT CHECKED" in result.summary


def test_an_empty_feed_is_reported_as_unusable():
    """Feodo Tracker after the takedowns: loaded, and proving nothing."""
    result = ThreatService(feeds=[_feed(rows="")]).match(
        [_connection("157.20.182.81", 425)]
    )
    assert result.checked_anything is False
    assert result.coverage.checked == 0
    assert any("EMPTY" in reason for reason in result.unusable_feeds)


def test_a_clean_result_with_a_real_feed_says_what_it_checked():
    result = ThreatService(feeds=[_feed()]).match([
        _connection("93.184.216.34", 443), _connection("8.8.8.8", 53),
    ])
    assert result.findings == []
    assert result.checked_anything is True
    assert result.coverage.checked == 2
    assert "checked against" in result.summary


def test_coverage_is_never_a_lie_about_what_was_compared():
    result = ThreatService(feeds=[]).match([
        _connection("1.2.3.4"), _connection("5.6.7.8"), _connection("127.0.0.1"),
    ])
    assert result.external_connections == 2
    assert result.coverage.checked == 0
    assert result.coverage.is_complete is False


def test_no_connections_with_good_feeds_is_not_the_same_as_no_feeds():
    """Three states, not two.

    An idle machine with working feeds has been checked properly and has
    nothing to report. An earlier version told it "NOT a clean bill of
    health", which is the crying-wolf failure this platform is built to
    avoid — and it showed up on the very first run of the finished verb.
    """
    idle = ThreatService(feeds=[_feed()]).match([_connection("127.0.0.1")])
    assert idle.checked_anything is True
    assert idle.had_nothing_to_check is True
    assert "No external connections to check" in idle.summary

    blind = ThreatService(feeds=[]).match([_connection("8.8.8.8")])
    assert blind.checked_anything is False
    assert blind.had_nothing_to_check is False
    assert "NOT CHECKED" in blind.summary


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
