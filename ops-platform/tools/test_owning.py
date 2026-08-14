"""Tests for the data-directory ownership guard.

Written against a real incident, 2026-07-27: a process on a different
machine had this platform's folder mounted, ran `patrol` and `corroborate`,
and wrote its own hostname into the operator's live state. 132 of 137
guard-journal entries, 11 of 25 findings, a device row and a phantom witness
observation — all well-formed, all indistinguishable from real records
afterwards. Nothing raised, because nothing was malformed.

The last test here reconstructs that incident and asserts it is now refused.

Run: python3 tools/test_owning.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.owning import (  # noqa: E402
    FOREIGN, OWNED, UNCLAIMED, adopt, guard, read_owner, refusal, state,
    write_owner,
)

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def temp_owner():
    return os.path.join(tempfile.mkdtemp(), "OWNER.json")


# --- the pure decision ------------------------------------------------------

def test_the_three_states():
    check(state(None, "acer") == UNCLAIMED, "no record: unclaimed")
    check(state({"machine_id": "acer"}, "acer") == OWNED, "same machine: owned")
    check(state({"machine_id": "win11"}, "acer") == FOREIGN, "different: foreign")


def test_a_record_without_a_machine_id_is_not_a_claim():
    """A half-written file must not lock anyone out of anything."""
    check(state({}, "acer") == UNCLAIMED, "empty dict claims nothing")
    check(state({"claimed_at": "2026-01-01"}, "acer") == UNCLAIMED,
          "a timestamp alone is not an owner")


# --- the file ---------------------------------------------------------------

def test_a_fresh_directory_is_claimed_silently_by_its_first_user():
    """Asking on day one would be a prompt nobody has context to answer."""
    path = temp_owner()
    check(guard("acer", "census", path) is None, "the first machine may run")
    check(read_owner(path)["machine_id"] == "acer", "and now owns the folder")


def test_the_owner_keeps_running():
    path = temp_owner()
    guard("acer", "census", path)
    check(guard("acer", "patrol", path) is None, "same machine, still fine")


def test_a_corrupt_claim_does_not_lock_the_operator_out():
    """The milder of two failures: re-claiming beats being unable to run.

    A tool that bricks itself over an unreadable metadata file has invented
    a new outage to prevent a hypothetical one.
    """
    path = temp_owner()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").write("{not json at all")
    check(read_owner(path) is None, "unreadable reads as no claim")
    check(guard("acer", "census", path) is None, "and the operator can work")


# --- the refusal ------------------------------------------------------------

def test_a_foreign_machine_is_refused():
    path = temp_owner()
    write_owner("example-host", path)
    message = guard("claude", "patrol", path)
    check(message is not None, "the other machine is stopped")
    check("REFUSED" in message, "and told so plainly")
    check("example-host" in message and "claude" in message,
          "both machine names appear, so it is obvious which is which")


def test_the_refusal_names_BOTH_ways_out():
    """A guard that only says no gets switched off."""
    message = refusal({"machine_id": "acer"}, "win11", "patrol")
    check("HUGINN_OBSERVATIONS_DIR" in message,
          "the second-witness case has its own answer and it is not adopt")
    check("./ops adopt" in message, "and a genuine replacement has one too")
    check("SECOND-WITNESS.md" in message, "with somewhere to read more")


def test_adopt_is_the_one_verb_allowed_through():
    path = temp_owner()
    write_owner("acer", path)
    check(guard("win11", "adopt", path) is None,
          "otherwise the documented way out would be unreachable")
    check(guard("win11", "census", path) is not None, "everything else stops")


# --- adoption ---------------------------------------------------------------

def test_adopting_transfers_ownership_and_says_what_it_does_not_fix():
    path = temp_owner()
    write_owner("old-machine", path)
    message = adopt("new-machine", path)
    check(read_owner(path)["machine_id"] == "new-machine", "ownership moved")
    check("still the other machine's" in message.lower(),
          "ownership is a lock, not a repair, and the verb says so")
    check("may report ordinary devices as NEW" in message,
          "with the concrete consequence, not a vague caution")
    check(read_owner(path)["note"].startswith("Adopted from old-machine"),
          "and the file records where it came from")


def test_adopting_your_own_directory_is_a_no_op():
    path = temp_owner()
    write_owner("acer", path)
    check("already belongs" in adopt("acer", path), "nothing to do, said plainly")


# --- the incident itself ----------------------------------------------------

def test_the_2026_07_27_contamination_is_now_refused():
    """The exact sequence that corrupted the operator's data.

    A second process, on a machine called `claude`, with the operator's
    data directory visible through a mount, running ordinary verbs. Every
    write is stamped with hostname(); nothing was malformed; nothing raised.
    """
    path = temp_owner()
    guard("example-host", "patrol", path)      # the operator, first

    for verb in ("patrol", "corroborate", "census", "triage", "wifi"):
        blocked = guard("claude", verb, path)
        check(blocked is not None, f"`{verb}` from the foreign machine is stopped")

    owner = read_owner(path)
    check(owner["machine_id"] == "example-host",
          "and the claim is unchanged — a refused run writes nothing at all")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
