"""Tests for corroboration — the second witness (chapter two, item 5).

Every guard finding rests on one machine's ARP cache, and one cache is
exactly what an ARP-spoofing attacker rewrites. Two hosts holding their own
caches can disagree, and the disagreement is worth more than either reading
alone.

The tests that matter most are the ones stopping this from manufacturing
false comfort:

  - agreement is never reported as proof
  - one witness is never reported as corroboration
  - a stale witness stops counting, and is SAID to have stopped
  - the same host's file twice is one witness, not two
  - a host that could not read its neighbours is present, not a witness

Everything is injected: no host is read, no file leaves a temp directory.

Run: python3 tools/test_corroboration.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.witnessing import (  # noqa: E402
    read_observations, write_observation,
)
from contracts.observation import Observation  # noqa: E402
from domains.corroboration import (  # noqa: E402
    assess, distinct_hosts, fresh, gateway_disagreement, verdict,
)

passed = 0
NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def obs(machine, gw_mac="aa:bb:cc:dd:ee:01", minutes_ago=1,
        neighbours=None, readable=True, gw_ip="192.168.1.1"):
    return Observation(
        machine_id=machine,
        observed_at=(NOW - timedelta(minutes=minutes_ago)).isoformat(),
        gateway_ip=gw_ip,
        gateway_mac=gw_mac,
        neighbours=neighbours if neighbours is not None else {"192.168.1.5": "11:22:33:44:55:66"},
        readable=readable,
    )


# --- the finding this whole feature exists for -----------------------------

def test_two_hosts_disagreeing_about_the_gateway_is_CRITICAL():
    """One of them has been given a false answer. That is ARP spoofing."""
    findings = gateway_disagreement(
        [obs("laptop", "aa:bb:cc:dd:ee:01"), obs("winbox", "de:ad:be:ef:00:99")],
        "laptop")
    check(len(findings) == 1, "one finding")
    check(findings[0].severity == "critical", "and it is critical")
    check(findings[0].confidence == "certain",
          "certain: the disagreement itself is a fact, whatever caused it")
    check("laptop" in findings[0].message and "winbox" in findings[0].message,
          "it names which host saw which MAC — the operator has to check both")
    check("security" in findings[0].tags, "tagged as security")


def test_hosts_agreeing_produce_no_finding():
    check(gateway_disagreement([obs("laptop"), obs("winbox")], "laptop") == [],
          "agreement is not a finding")


def test_a_host_with_no_gateway_entry_is_not_a_disagreement():
    """Absence of an ARP entry is not a conflicting ARP entry.

    A host that has not spoken to the gateway recently simply has no row for
    it. Treating that as disagreement would fire critical alerts at any
    machine that had been idle.
    """
    check(gateway_disagreement([obs("laptop"), obs("winbox", gw_mac=None)],
                               "laptop") == [],
          "a missing entry is silence, not contradiction")


# --- the three refusals ----------------------------------------------------

def test_one_witness_corroborates_nothing():
    state = verdict([obs("laptop")], NOW)
    check(state["can_corroborate"] is False, "one host cannot corroborate")
    check(state["gateway_agreement"] is None,
          "and reports agreement as UNKNOWN, not as True")
    check(assess([obs("laptop")], "laptop", NOW) == [],
          "and produces no findings from a single cache")


def test_the_same_host_twice_is_ONE_witness():
    """Two files, one machine, is an echo — not a second opinion."""
    twice = [obs("laptop", minutes_ago=1), obs("laptop", minutes_ago=2)]
    check(distinct_hosts(twice) == 1, "one distinct host")
    check(verdict(twice, NOW)["can_corroborate"] is False,
          "so it still cannot corroborate")


def test_agreement_is_reported_as_agreement_never_as_proof():
    """The verdict exposes a fact, not a verdict about safety.

    Two hosts can agree and both be lied to — one attacker poisoning both
    caches produces perfect consensus. Nothing here may say 'safe'.
    """
    state = verdict([obs("laptop"), obs("winbox")], NOW)
    check(state["gateway_agreement"] is True, "they agree")
    check("safe" not in json.dumps(state).lower(), "and the word 'safe' is absent")


# --- staleness: an old witness is not a witness ----------------------------

def test_a_stale_observation_stops_counting_and_is_named():
    usable, stale = fresh([obs("laptop", minutes_ago=1),
                           obs("winbox", minutes_ago=600)], NOW)
    check([o.machine_id for o in usable] == ["laptop"], "only the fresh one counts")
    check([o.machine_id for o in stale] == ["winbox"], "the old one is stale")
    state = verdict([obs("laptop"), obs("winbox", minutes_ago=600)], NOW)
    check(state["can_corroborate"] is False, "which drops it back to one witness")
    check(state["stale"] == ["winbox"],
          "and it is REPORTED stale, never silently dropped")


def test_an_undated_observation_is_treated_as_stale():
    """The safe direction: drop a witness we cannot date rather than count
    one that may describe last week."""
    undated = Observation(machine_id="winbox", observed_at="not-a-date",
                          gateway_mac="de:ad:be:ef:00:99", gateway_ip="192.168.1.1")
    usable, stale = fresh([obs("laptop"), undated], NOW)
    check(len(usable) == 1 and stale[0].machine_id == "winbox",
          "an unparseable timestamp does not become a fresh witness")


def test_small_clock_skew_is_tolerated():
    """A peer whose clock is two minutes fast is still a witness."""
    usable, _ = fresh([obs("laptop"), obs("winbox", minutes_ago=-2)], NOW)
    check(len(usable) == 2, "two minutes into the future is not disqualifying")


def test_a_wildly_future_timestamp_is_not_trusted():
    usable, stale = fresh([obs("laptop"), obs("winbox", minutes_ago=-600)], NOW)
    check(len(usable) == 1 and stale[0].machine_id == "winbox",
          "ten hours in the future is a broken clock, not a fresh reading")


# --- blindness is not silence ----------------------------------------------

def test_a_host_that_could_not_read_is_present_but_not_a_witness():
    """`readable=False` must never look like 'saw nothing'."""
    blind = obs("winbox", neighbours={}, readable=False)
    state = verdict([obs("laptop"), blind], NOW)
    check(state["unreadable"] == ["winbox"], "its blindness is reported")
    findings = assess([obs("laptop"), blind], "laptop", NOW)
    check(all("corroboration_gateway" not in f.id for f in findings),
          "and it raises no conflict merely by being empty")


def test_coverage_counts_only_the_hosts_that_could_actually_see():
    findings = gateway_disagreement(
        [obs("laptop", "aa:bb:cc:dd:ee:01"),
         obs("winbox", "de:ad:be:ef:00:99", readable=False)], "laptop")
    check(findings[0].coverage.checked == 1 and findings[0].coverage.total == 2,
          "1 of 2 hosts could read — the finding carries that, as everything here does")


# --- partial visibility is context, not an alarm ---------------------------

def test_devices_seen_by_only_one_host_are_INFO():
    """Ordinary on a switched network. Alarming on it would be noise."""
    findings = assess(
        [obs("laptop", neighbours={"192.168.1.5": "aa:11"}),
         obs("winbox", neighbours={"192.168.1.9": "bb:22"})], "laptop", NOW)
    partial = [f for f in findings if f.id == "corroboration_partial_visibility"]
    check(len(partial) == 1 and partial[0].severity == "info",
          "reported, and only as information")
    check("Normal on a switched network" in partial[0].suggested_action,
          "and it explains why this is usually nothing")


# --- the file transport ----------------------------------------------------

def test_an_observation_round_trips_through_disk():
    directory = tempfile.mkdtemp()
    original = obs("laptop")
    path = write_observation(original, directory)
    check(os.path.exists(path), "written")
    back = read_observations(directory)
    check(len(back) == 1, "read back")
    check(back[0].gateway_mac == original.gateway_mac, "content survives")
    check(back[0].machine_id == "laptop", "and so does the witness's name")


def test_a_machine_name_cannot_escape_the_directory():
    """machine_id reaches this from another host's file. It is a filename."""
    directory = tempfile.mkdtemp()
    path = write_observation(obs("../../etc/passwd"), directory)
    check(os.path.dirname(os.path.abspath(path)) == os.path.abspath(directory),
          "the file lands inside the directory, whatever the name claimed")


def test_one_corrupt_file_does_not_hide_the_readable_ones():
    directory = tempfile.mkdtemp()
    write_observation(obs("laptop"), directory)
    with open(os.path.join(directory, "observation-broken.json"), "w",
              encoding="utf-8") as handle:
        handle.write("{ not json")
    back = read_observations(directory)
    check([o.machine_id for o in back] == ["laptop"],
          "the good witness is still returned")


def test_a_missing_directory_is_empty_not_an_error():
    check(read_observations(os.path.join(tempfile.mkdtemp(), "nope")) == [],
          "nothing to read is a state, not a crash")


def test_a_partial_record_degrades_rather_than_raising():
    """The file may come from another OS or an older version."""
    back = Observation.from_dict({"machine_id": "winbox"})
    check(back.machine_id == "winbox", "what is there is kept")
    check(back.neighbours == {} and back.gateway_mac is None,
          "what is missing becomes empty, not an exception")
    check(Observation.from_dict({}).machine_id == "unknown",
          "and an empty record still names itself")


# --- the shared folder, which is how two machines actually meet -----------

def test_the_observations_directory_follows_the_environment():
    """Both machines point HUGINN_OBSERVATIONS_DIR at one folder.

    Re-read per call rather than captured at import: a long-running server
    would otherwise never notice, and the scheduled runners set it in their
    own environment.
    """
    import agents.witnessing as witnessing

    before = os.environ.get("HUGINN_OBSERVATIONS_DIR")
    shared = tempfile.mkdtemp()
    try:
        os.environ["HUGINN_OBSERVATIONS_DIR"] = shared
        check(witnessing.observation_dir() == shared, "the env var is honoured")
        path = witnessing.write_observation(obs("laptop"))
        check(path.startswith(shared), "and writes land in the shared folder")
        check([o.machine_id for o in witnessing.read_observations()] == ["laptop"],
              "and reads come back from it")
    finally:
        if before is None:
            os.environ.pop("HUGINN_OBSERVATIONS_DIR", None)
        else:
            os.environ["HUGINN_OBSERVATIONS_DIR"] = before

    check(witnessing.observation_dir().endswith("observations"),
          "unset falls back to the local default")


def test_two_machines_sharing_one_folder_corroborate():
    """The end-to-end shape of item 5, without needing two machines."""
    import agents.witnessing as witnessing

    shared = tempfile.mkdtemp()
    witnessing.write_observation(obs("laptop", "aa:bb:cc:dd:ee:01"), shared)
    witnessing.write_observation(obs("winbox", "aa:bb:cc:dd:ee:01"), shared)
    both = witnessing.read_observations(shared)
    check(verdict(both, NOW)["can_corroborate"] is True,
          "two files from two machines in one folder = corroboration")

    # now the windows box is lied to
    witnessing.write_observation(obs("winbox", "de:ad:be:ef:00:99"), shared)
    findings = assess(witnessing.read_observations(shared), "laptop", NOW)
    critical = [f for f in findings if f.severity == "critical"]
    check(len(critical) == 1, "and a spoofed gateway on either host is caught")


def test_a_failed_write_is_reported_not_read_as_an_empty_folder():
    """The live bug: a write that FAILED read as "nothing written yet".

    On the first real shared-folder run the mount had not happened, so the
    path was a root-owned local directory. `record` hit permission denied,
    swallowed it, and the verb reported a benign empty state -- sending the
    operator to look at the OTHER machine for a file this one had never
    managed to produce.
    """
    import skills.corroborate as verb

    before = os.environ.get("HUGINN_OBSERVATIONS_DIR")
    try:
        # A path that CANNOT be created, on every OS: its parent is a file,
        # not a directory, so os.makedirs raises. The first version made a
        # directory read-only with `chmod 0o500` — which blocks writes on
        # POSIX and is IGNORED on Windows, where the owner writes into a
        # read-only directory regardless. The test then passed on Linux and
        # failed on Windows: the disc doing exactly its job, catching a test
        # that only proved the point on the OS it was written on.
        parent = tempfile.NamedTemporaryFile(delete=False)
        parent.close()
        blocked = os.path.join(parent.name, "observations")
        os.environ["HUGINN_OBSERVATIONS_DIR"] = blocked
        out = verb.skill_corroborate("")
        check("COULD NOT WRITE" in out,
              "the failure to write is stated, loudly")
        check("not an all-clear" in out,
              "and explicitly refused as an all-clear")
        check(blocked in out, "and the path it could not write is named")
    finally:
        os.unlink(parent.name)
        if before is None:
            os.environ.pop("HUGINN_OBSERVATIONS_DIR", None)
        else:
            os.environ["HUGINN_OBSERVATIONS_DIR"] = before


def test_a_successful_write_adds_no_warning():
    """The warning must not cry wolf on the normal path."""
    import skills.corroborate as verb

    before = os.environ.get("HUGINN_OBSERVATIONS_DIR")
    try:
        os.environ["HUGINN_OBSERVATIONS_DIR"] = tempfile.mkdtemp()
        out = verb.skill_corroborate("")
        check("COULD NOT WRITE" not in out, "a writable folder raises no warning")
    finally:
        if before is None:
            os.environ.pop("HUGINN_OBSERVATIONS_DIR", None)
        else:
            os.environ["HUGINN_OBSERVATIONS_DIR"] = before


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
