"""Rule 5 — a host that saw NOTHING is not a witness.

Split out of `test_corroboration.py` (which hit the 400-line limit) because
these tests come from a distinct incident and assert a distinct rule.

**The incident, 2026-07-27.** A process on a machine with no LAN visibility
had the operator's observations folder mounted and wrote a perfectly
well-formed observation into it: `readable: true`, correctly dated, no
gateway, no neighbours. Nothing was malformed, so nothing raised.

It was counted as a witness. `corroborate` reported "2 hosts witnessing",
and `only_one_host_sees` then compared a real fourteen-device network
against an empty set and reported every one of those devices as "seen by
only one of 2 hosts" — a page of findings manufactured out of nothing.

The lesson is small and sharp: **`readable` means the tool ran.** It says
nothing about whether there was a network in front of it, and the gap
between those two facts is exactly the shape of a false witness.

Run: python3 tools/test_blind_witness.py
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.observation import Observation  # noqa: E402
from domains.corroboration import (  # noqa: E402
    assess, fresh, saw_nothing, verdict,
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
        gateway_ip=gw_ip, gateway_mac=gw_mac,
        neighbours=neighbours if neighbours is not None
        else {"192.168.1.5": "11:22:33:44:55:66"},
        readable=readable,
    )


def _blind(machine="ghost", minutes_ago=1):
    """The exact file the incident produced: valid, current, and empty."""
    return Observation(
        machine_id=machine,
        observed_at=(NOW - timedelta(minutes=minutes_ago)).isoformat(),
        gateway_ip=None, gateway_mac=None, neighbours={}, readable=True,
    )


def test_an_empty_observation_is_recognised_as_having_seen_nothing():
    check(saw_nothing(_blind()), "no gateway and no neighbours is not a sighting")
    check(not saw_nothing(obs("acer")), "a real observation is not blind")


def test_readable_does_not_mean_it_saw_anything():
    """`readable` says the TOOL ran. The gap between those is the bug."""
    ghost = _blind()
    check(ghost.readable, "it reported success, which is why it slipped through")
    usable, stale = fresh([obs("acer"), ghost], NOW)
    check([o.machine_id for o in usable] == ["acer"], "only the real host counts")
    check(ghost in stale, "and the empty one is set aside, not dropped in silence")


def test_a_blind_host_no_longer_manufactures_partial_visibility_findings():
    """The actual damage: every real device reported as a disagreement.

    With the ghost counted, `only_one_host_sees` compared a real network
    against an empty set and reported all 14 of the operator's devices as
    "seen by only one of 2 hosts" — a page of findings generated out of
    nothing at all.
    """
    real = obs("acer", neighbours={f"192.168.1.{n}": f"aa:bb:cc:dd:ee:{n:02d}"
                                   for n in range(2, 16)})
    check(assess([real, _blind()], "acer", NOW) == [],
          "one real witness plus one blind one produces NO findings")


def test_the_verdict_separates_went_quiet_from_saw_nothing():
    """Different problems, different fixes, so they are reported apart."""
    state = verdict([obs("acer"), _blind(), obs("old", minutes_ago=600)], NOW)
    check(state["blind"] == ["ghost"], "the empty host is named as blind")
    check(state["stale"] == ["old"], "and the absent one as stale")
    check(state["host_count"] == 1,
          "neither is counted — the operator has ONE witness and is told so")


def test_a_blind_host_cannot_create_a_false_second_witness():
    """The headline claim that started the whole investigation."""
    state = verdict([obs("acer"), _blind()], NOW)
    check(state["hosts"] == ["acer"], "one host witnessing, correctly")
    check(state["can_corroborate"] is False,
          "and corroboration is honestly reported as impossible")



if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
