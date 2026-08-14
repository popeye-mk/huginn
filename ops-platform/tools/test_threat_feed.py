"""Tests for threat-feed loading and matching (R8).

**Fixtures are real rows** captured from a live ThreatFox export on
2026-07-21, not invented ones. Every field quirk below was observed
rather than imagined: values arrive quoted *and* space-padded, comment
lines start with `#`, and the header carries the generation time.

The tests are mostly about the three states a feed can be in, which is
the lesson the Feodo Tracker download taught by arriving with **1 entry,
139 days old**:

| state | why it matters |
| - | - |
| absent | nobody configured a feed |
| empty | loaded, zero entries — matching proves nothing |
| **stale** | entries exist but stopped being true months ago |

The third is the dangerous one: matching proceeds, finds nothing, and
reports a clean result from dead data.

Run: python3 tools/test_threat_feed.py
"""

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.indicator import Indicator  # noqa: E402
from storage.threat_feed import STALE_AFTER_DAYS, ThreatFeed, load_feeds  # noqa: E402

HEADER = """\
################################################################
# ThreatFox IOCs: recent additions - CSV format                #
# Last updated: {stamp} UTC                        #
#                                                              #
# Terms Of Use: https://threatfox.abuse.ch/faq/#tos            #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware",\
"malware_alias","malware_printable","last_seen_utc","confidence_level",\
"is_compromised","reference","tags","anonymous","reporter"
"""

# Real rows, copied from the live export.
ROWS = """\
"2026-07-21 05:35:20", "1854731", "157.20.182.81:425", "ip:port", "botnet_cc", \
"win.tofsee", "Gheg", "Tofsee", "", "75", "False", "", "Tofsee", "0", "abuse_ch"
"2026-07-21 05:28:01", "1854730", "ewmc.jenslittlerugrats.org", "domain", \
"payload_delivery", "js.clearfake", "None", "ClearFake", "", "100", "False", \
"None", "ClearFake,win-0x0cd5,windows", "1", "anonymous"
"2026-07-21 05:21:34", "1854589", "chauvet.club", "domain", "botnet_cc", \
"js.kongtuke", "TAG-124,js.LandUpdate808", "KongTuke", "", "50", "False", "", \
"KongTuke", "0", "skocherhan"
"2026-07-21 05:20:00", "1854588", "203.0.113.99:8080", "ip:port", "botnet_cc", \
"win.example", "None", "ExampleBot", "", "30", "True", "", "Example", "0", "tester"
"""


def _feed(days_old=0, rows=ROWS, name="threatfox"):
    stamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    path = Path(tempfile.mkdtemp()) / f"{name}.csv"
    path.write_text(HEADER.format(stamp=stamp) + rows, encoding="utf-8")
    return ThreatFeed(path)


# --- parsing real rows ----------------------------------------------------

def test_a_real_export_parses():
    feed = _feed()
    assert feed.status.loaded
    assert feed.status.entry_count == 4


def test_quoted_and_space_padded_fields_are_stripped():
    """The live export emits `, "ip:port"` — leading spaces inside quotes."""
    indicator = _feed().match_address("157.20.182.81", 425)
    assert indicator is not None
    assert indicator.ioc_type == "ip:port"
    assert indicator.malware == "Tofsee"


def test_comment_lines_are_not_indicators():
    assert _feed().status.entry_count == 4   # header lines excluded


def test_a_malformed_row_costs_only_itself():
    feed = _feed(rows=ROWS + '"broken","row"\n')
    assert feed.status.entry_count == 4


# --- what a match is allowed to claim -------------------------------------

def test_the_feeds_own_confidence_is_carried_not_invented():
    """The feed says 75, 100, 50, 30. We must not round any of them to 'bad'."""
    feed = _feed()
    assert feed.match_address("157.20.182.81", 425).confidence == "likely"    # 75
    assert feed.match_domain("ewmc.jenslittlerugrats.org").confidence == "certain"  # 100
    assert feed.match_domain("chauvet.club").confidence == "likely"           # 50
    assert feed.match_address("203.0.113.99", 8080).confidence == "possible"  # 30


def test_a_compromised_host_is_flagged_as_such():
    """A hacked legitimate site and a malicious one need different fixes.

    Blocking the second is free; blocking the first blocks a real
    business. Dropping the distinction would make the platform advise
    the same action for both.
    """
    indicator = _feed().match_address("203.0.113.99", 8080)
    assert indicator.is_compromised is True
    assert "compromised legitimate host" in indicator.description


def test_an_indicator_must_name_its_feed():
    """Attribution is a licence condition and a checkability requirement."""
    try:
        Indicator(value="1.2.3.4", ioc_type="ip", feed="")
    except ValueError as exc:
        assert "feed" in str(exc)
        return
    raise AssertionError("an unattributed indicator was accepted")


# --- matching -------------------------------------------------------------

def test_port_is_used_when_the_feed_published_one():
    """`157.20.182.81:425` is address AND port; matching only the address
    throws away half the evidence the feed gave us."""
    feed = _feed()
    indicator = feed.match_address("157.20.182.81", 425)
    assert indicator.port == 425
    assert indicator.address == "157.20.182.81"


def test_an_address_with_no_indicator_matches_nothing():
    assert _feed().match_address("8.8.8.8", 443) is None
    assert _feed().match_domain("example.com") is None


def test_domain_matching_is_case_and_dot_insensitive():
    feed = _feed()
    assert feed.match_domain("CHAUVET.CLUB") is not None
    assert feed.match_domain("chauvet.club.") is not None


def test_hashes_and_urls_are_kept_but_not_matchable():
    """Carried so parsing does not silently drop rows; excluded from
    matching because nothing here observes a file hash."""
    indicator = Indicator(value="d41d8cd9", ioc_type="md5_hash", feed="x")
    assert indicator.is_matchable is False


# --- the three states -----------------------------------------------------

def test_an_absent_feed_says_so_rather_than_crashing():
    feed = ThreatFeed(Path(tempfile.mkdtemp()) / "missing.csv")
    assert feed.status.loaded is False
    assert feed.status.is_usable is False
    assert "no feed file" in feed.status.reason


def test_an_empty_feed_is_distinguished_from_a_missing_one():
    """Feodo Tracker after the Emotet takedowns: loaded, and useless."""
    feed = _feed(rows="")
    assert feed.status.loaded is True
    assert feed.status.entry_count == 0
    assert feed.status.is_usable is False
    assert "EMPTY" in feed.status.summary


def test_a_stale_feed_is_flagged_even_though_it_has_entries():
    """The dangerous state. Matching succeeds against data that died."""
    feed = _feed(days_old=STALE_AFTER_DAYS + 100)
    assert feed.status.entry_count == 4
    assert feed.status.is_usable is True
    assert feed.status.is_stale is True
    assert "STALE" in feed.status.summary


def test_a_fresh_feed_is_not_flagged_stale():
    feed = _feed(days_old=1)
    assert feed.status.is_stale is False
    assert "STALE" not in feed.status.summary


def test_feed_age_comes_from_the_header_not_the_download_time():
    """A fresh download of a dead feed is still a dead feed.

    The file mtime says when we fetched it; the header says when
    abuse.ch generated it. Only the second one is about the data.
    """
    feed = _feed(days_old=200)          # header old, file written just now
    assert feed.status.age_days >= 199


def test_an_empty_feed_directory_is_a_valid_state():
    assert load_feeds(Path(tempfile.mkdtemp())) == []
    assert load_feeds(Path("/nonexistent/feeds")) == []


# --- two feeds, two formats, one organisation -----------------------------

FEODO = """\
#####################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist     #
# Last updated: {stamp} UTC                         #
#####################################################
#
# DstIP
50.16.16.211
192.0.2.44
# END 2 entries
"""


def _feodo(days_old=0):
    stamp = (datetime.now(timezone.utc) - timedelta(days=days_old)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    path = Path(tempfile.mkdtemp()) / "feodotracker.csv"
    path.write_text(FEODO.format(stamp=stamp), encoding="utf-8")
    return ThreatFeed(path)


def test_the_plain_ip_format_is_parsed_too():
    """Found by the first live run on a real machine.

    Both feeds come from abuse.ch and both were saved as `.csv`, but
    ThreatFox exports quoted 15-column CSV while Feodo Tracker ships one
    bare IP per line. The ThreatFox-only parser produced zero indicators
    and the status read 'loaded but EMPTY' — accidentally true for a
    feed that had been emptied by law enforcement, and silently wrong
    for any feed that had not.
    """
    feed = _feodo()
    assert feed.status.entry_count == 2
    assert feed.status.is_usable
    assert feed.match_address("50.16.16.211", 443) is not None


def test_the_parser_is_chosen_by_shape_not_by_filename():
    """Both files are named `.csv`; only one of them is CSV."""
    assert _feed().status.entry_count == 4       # ThreatFox rows
    assert _feodo().status.entry_count == 2      # bare addresses


def test_unreadable_is_not_reported_as_empty():
    """'We could not read this' and 'there is nothing here' differ.

    The whole reason the live Feodo bug was worth fixing rather than
    shrugging at: an unrecognised format must not look like an absence
    of threats.
    """
    path = Path(tempfile.mkdtemp()) / "weird.csv"
    path.write_text("# header\nnot,an,ip\nzzz\n", encoding="utf-8")
    feed = ThreatFeed(path)

    assert feed.status.loaded is True
    assert feed.status.is_usable is False
    assert feed.status.unparseable_rows == 2
    assert "UNREADABLE" in feed.status.summary
    assert "parser gap" in feed.status.summary
    assert "EMPTY" not in feed.status.summary


def test_a_bare_address_feed_does_not_overclaim_confidence():
    """A bare line carries no confidence field, so `certain` is unearned.

    Feodo only lists an address after it answers with a valid botnet C2
    response — a strong claim — but the line itself says nothing more,
    and the contract should reflect what is written, not what is meant.
    """
    indicator = _feodo().match_address("50.16.16.211", 443)
    assert indicator.confidence == "likely"
    assert indicator.confidence != "certain"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
