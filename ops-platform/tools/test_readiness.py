"""Tests for the console status strip.

Almost every test here is about the same thing from a different angle: **a
fact that could not be read must not render as health.** The strip has three
states so that "I could not tell" has somewhere to go that is not green, and
these tests are what stops a future edit from quietly collapsing it to two.

The case that motivated the module is `test_a_silent_journal_is_not_a_quiet
_patrol`: before the heartbeat existed, a guard running hourly and a guard
that stopped a week ago produced identical evidence — an empty change
journal. There was no wrong green light; there was no light, which the eye
reads as calm.

Run: python3 tools/test_readiness.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.observation import Observation  # noqa: E402
from domains.readiness import (  # noqa: E402
    ATTENTION, OK, UNKNOWN, age_phrase, alerting_cell, inventory_cell,
    patrol_cell, strip, witness_cell, worst,
)

passed = 0

NOW = datetime(2026, 7, 27, 15, 0, tzinfo=timezone.utc)


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def ago(**kwargs):
    return (NOW - timedelta(**kwargs)).isoformat()


def observation(machine, **kwargs):
    return Observation(machine_id=machine,
                       observed_at=kwargs.pop("at", ago(minutes=10)), **kwargs)


# --- 1. the patrol heartbeat -----------------------------------------------

def test_a_silent_journal_is_not_a_quiet_patrol():
    """No heartbeat means the schedule is unproven, not that all is well.

    This is the whole reason the heartbeat exists: a patrol that finds
    nothing writes nothing to the change journal, so "quiet" and "stopped"
    were indistinguishable. Nothing may infer calm from silence.
    """
    cell = patrol_cell(None, NOW)
    check(cell.state == UNKNOWN, "never green on missing evidence")
    check("check the timer" in cell.sub,
          "and it points at the schedule, not at the network")


def test_a_recent_quiet_pass_reads_ok_and_says_so():
    cell = patrol_cell({"ts": ago(minutes=14), "attention": 0}, NOW)
    check(cell.state == OK, "a pass 14 minutes ago is current")
    check("nothing above info" in cell.sub,
          "and 'quiet' is reported as a READING, taken from the pass itself")


def test_a_pass_that_found_something_says_how_many():
    cell = patrol_cell({"ts": ago(minutes=5), "attention": 3}, NOW)
    check("3 worth your attention" in cell.sub, "the count is not swallowed")


def test_a_stale_heartbeat_is_attention_not_ok():
    """One missed hour is a sleeping laptop; several is a stopped timer."""
    check(patrol_cell({"ts": ago(hours=9)}, NOW).state == ATTENTION,
          "nine hours without a pass is worth saying out loud")
    check(patrol_cell({"ts": ago(minutes=95)}, NOW).state == OK,
          "but a single missed window is not an alarm")


def test_an_unparseable_timestamp_is_unknown_not_now():
    """Defaulting a bad stamp to now() would forge a fresh patrol."""
    check(patrol_cell({"ts": "yesterday-ish"}, NOW).state == UNKNOWN,
          "garbage in the heartbeat reads as no heartbeat")


def test_age_never_overstates_freshness():
    check(age_phrase(NOW - timedelta(seconds=119), NOW) == "1 minutes ago",
          "rounded down")
    check(age_phrase(NOW - timedelta(seconds=30), NOW) == "just now", "under 90s")
    check(age_phrase(NOW - timedelta(days=3), NOW) == "3 days ago", "days")


# --- 2. would anyone actually be told? -------------------------------------

def test_no_channel_enabled_is_attention():
    cell = alerting_cell({"desktop": {"enabled": False}})
    check(cell.state == ATTENTION, "silence is not a configuration")
    check("nobody is told" in cell.value, "and it is said plainly")


def test_desktop_only_is_attention_because_it_cannot_reach_you_elsewhere():
    """A real channel that works, and still cannot do the job alone.

    Alerting exists for the case where you are NOT at the machine. A toast
    on a screen nobody is sitting at is a recorded finding with extra steps.
    """
    cell = alerting_cell({"desktop": {"enabled": True}})
    check(cell.state == ATTENTION, "not green")
    check("only while you are at this machine" in cell.sub, "and it says why")


def test_a_remote_channel_reads_ok_but_claims_nothing_about_delivery():
    cell = alerting_cell({"desktop": {"enabled": True},
                          "ntfy": {"enabled": True},
                          "min_severity": "warning"})
    check(cell.state == OK, "a channel that reaches an absent operator")
    check("nothing is proven until a test alert arrives" in cell.sub,
          "enabled is not delivered, and the cell refuses to imply otherwise")


# --- 3. witnesses ----------------------------------------------------------

def test_one_witness_is_attention_and_names_the_limit():
    cell = witness_cell([observation("acer")], "acer", NOW)
    check(cell.state == ATTENTION, "a single cache cannot be corroborated")
    check("nothing to compare it against" in cell.sub, "the limit is stated")


def test_two_witnesses_read_ok():
    cell = witness_cell([observation("acer"), observation("win11")],
                        "acer", NOW)
    check(cell.state == OK and "2 reporting" in cell.value, "two hosts")


def test_a_stale_peer_does_not_count_as_a_witness():
    """An old observation is evidence about the past, not about now."""
    cell = witness_cell([observation("acer"),
                         observation("win11", at=ago(days=4))], "acer", NOW)
    check(cell.state == ATTENTION, "the stale host does not make it two")
    check("win11" in cell.sub, "and the operator is told which one went quiet")


def test_no_observation_at_all_is_unknown():
    check(witness_cell([], "acer", NOW).state == UNKNOWN,
          "nothing reporting is not one witness; it is no reading")


# --- 4. the inventory headline, and the strip as a whole -------------------

def test_the_inventory_cell_carries_the_domains_own_verdict():
    cell = inventory_cell({"state": ATTENTION, "value": "6 unconfirmed",
                           "sub": "3 of them here now"})
    check(cell.state == ATTENTION and "6 unconfirmed" in cell.value,
          "no second opinion is invented here")
    check(inventory_cell(None).state == UNKNOWN, "and nothing defaults to ok")


def test_the_strip_is_four_cells_in_reading_order():
    cells = strip(machine_id="acer", now=NOW)
    check(len(cells) == 4, "four cells")
    check([c.key for c in cells][0] == "Last patrol",
          "the guard's own liveness is read first — everything else "
          "describes a machine it may not be watching")


def test_one_blind_spot_is_never_averaged_away():
    """Three greens and an unknown is not 'mostly fine'."""
    cells = strip(last_pass={"ts": ago(minutes=5)},
                  admin={"ntfy": {"enabled": True}},
                  observations=[observation("a"), observation("b")],
                  machine_id="a",
                  inventory_head={"state": UNKNOWN, "value": "partly unread"},
                  now=NOW)
    check(worst(cells) == UNKNOWN, "the gap sets the overall state")


def test_attention_outranks_unknown():
    """A thing known to be wrong beats a thing not known."""
    cells = strip(last_pass={"ts": ago(hours=20)}, admin={},
                  observations=[], machine_id="a", now=NOW)
    check(worst(cells) == ATTENTION, "something is definitely wrong: say that")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
