"""Am I actually covered? — the four cells at the top of the console.

Pure. Facts in, `Cell`s out. No file is opened here and no clock is read
that was not passed in, so every branch below is reachable from a test.

**Three states, and the third is the point.** `ok`, `attention`, `unknown`.
Most status widgets have two, which forces every "I could not tell" into
one of them — and it always lands on green, because green is the resting
state. That is the failure this whole tool was built to refuse, so it is
not permitted in the tool's own status strip: a fact that could not be
read renders `unknown` and says what was not read.

A worked example of why this matters more than it sounds. Until this
module existed, "is the hourly patrol still running?" was answered by
looking at the change journal — and a patrol that finds nothing writes
nothing to it. A patrol running quietly every hour and a patrol that
stopped a week ago produced the identical, empty evidence. There was no
green light to be wrong; there was no light at all, which the eye reads as
fine. `patrol_cell` therefore reads a heartbeat written on EVERY pass, and
says `unknown` when there is none rather than inferring calm from silence.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Sequence

OK = "ok"
ATTENTION = "attention"
UNKNOWN = "unknown"

#: The patrol timer's period. Twice this is the staleness threshold — one
#: missed window is a laptop that was asleep, two is a schedule to check.
PATROL_EVERY_HOURS = 1


@dataclass(frozen=True)
class Cell:
    """One reading. `sub` carries the caveat, and is never decoration."""

    key: str
    value: str
    sub: str = ""
    state: str = UNKNOWN

    def as_dict(self) -> dict:
        return {"key": self.key, "value": self.value,
                "sub": self.sub, "state": self.state}


def _parse(stamp) -> Optional[datetime]:
    """An ISO timestamp, or None. Anything unparseable is None, not now()."""
    if isinstance(stamp, datetime):
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age_phrase(then: datetime, now: datetime) -> str:
    """Human elapsed time. Rounded down, so it never overstates freshness."""
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 90:
        return "just now"
    if seconds < 5400:
        return f"{seconds // 60} minutes ago"
    if seconds < 172800:
        return f"{seconds // 3600} hours ago"
    return f"{seconds // 86400} days ago"


# --- 1. is the guard actually running? -------------------------------------

def patrol_cell(last_pass: Optional[dict], now: datetime,
                every_hours: int = PATROL_EVERY_HOURS) -> Cell:
    """When the guard last ran, and what it concluded.

    Never green on missing evidence. "No heartbeat" is the signature of a
    timer that stopped, which is the one failure that would otherwise leave
    every other cell on this strip describing a machine nobody is watching.
    """
    when = _parse((last_pass or {}).get("ts"))
    if when is None:
        return Cell("Last patrol", "never recorded", state=UNKNOWN,
                    sub="no pass has written a heartbeat — check the timer, "
                        "not the network")

    age_hours = (now - when).total_seconds() / 3600.0
    attention = int((last_pass or {}).get("attention") or 0)
    verdict = (f"{attention} worth your attention" if attention
               else "nothing above info")

    if age_hours > 2 * every_hours:
        return Cell("Last patrol", age_phrase(when, now), state=ATTENTION,
                    sub=f"expected every {every_hours}h — the schedule may "
                        f"have stopped, or this machine was off")
    return Cell("Last patrol", age_phrase(when, now), state=OK,
                sub=f"every {every_hours}h · {verdict}")


# --- 2. would anyone be told? ----------------------------------------------

def alerting_cell(admin: Optional[dict]) -> Cell:
    """Which channels are on, judged by whether they reach an absent person.

    Desktop-only is `attention` rather than `ok` on purpose. It is a real
    channel and it works, but it delivers to a screen the operator has to
    already be sitting at — so on its own it cannot answer the case the
    alerting exists for, which is being told while you are somewhere else.
    """
    admin = admin or {}
    on = [name for name, key in (("desktop", "desktop"), ("phone", "ntfy"),
                                 ("email", "email"))
          if (admin.get(key) or {}).get("enabled")]
    if not on:
        return Cell("If something happens", "nobody is told", state=ATTENTION,
                    sub="findings are recorded, but no channel is enabled")
    remote = [n for n in on if n != "desktop"]
    floor = admin.get("min_severity") or "warning"
    if not remote:
        return Cell("If something happens", "desktop only", state=ATTENTION,
                    sub="reaches you only while you are at this machine")
    return Cell("If something happens", " + ".join(on), state=OK,
                sub=f"at {floor} and above · nothing is proven until a test "
                    f"alert arrives")


# --- 3. how many machines are looking? -------------------------------------

def witness_cell(observations: Optional[Sequence], machine_id: str,
                 now: datetime, stale_hours: int = 24) -> Cell:
    """How many hosts are reporting what they see.

    One witness is `attention`, not `ok`, and that is a standing limit
    rather than a fault: a single ARP cache cannot be checked against
    anything, so the attack that rewrites it is invisible from inside.
    """
    seen = list(observations or [])
    fresh, stale = [], []
    for obs in seen:
        when = _parse(getattr(obs, "observed_at", None))
        name = getattr(obs, "machine_id", "") or "?"
        if when is not None and (now - when).total_seconds() <= stale_hours * 3600:
            fresh.append(name)
        else:
            stale.append(name)

    if not fresh:
        return Cell("Witnesses", "none reporting", state=UNKNOWN,
                    sub="no observation file is current — nothing can be "
                        "cross-checked")
    gone = ", ".join(sorted({n for n in stale if n != machine_id})[:2])
    others = [n for n in fresh if n != machine_id]
    if not others:
        # A peer that WENT quiet is named here rather than dropped. Falling
        # back to a bare "this machine only" would describe a host that
        # never had a second witness and a host whose second witness died
        # last Tuesday in exactly the same words — and only one of those is
        # a standing limit rather than something to go and fix.
        sub = "one ARP cache, with nothing to compare it against"
        if gone:
            sub = f"{sub} · {gone} has stopped reporting"
        return Cell("Witnesses", "1 — this machine only", state=ATTENTION,
                    sub=sub)
    note = f"{len(others)} other host(s) agreeing or disagreeing"
    if gone:
        note += f" · stale: {gone}"
    return Cell("Witnesses", f"{len(fresh)} reporting", state=OK, sub=note)


# --- 4. what is on the network that nobody has vouched for? ----------------

def inventory_cell(head: Optional[dict]) -> Cell:
    """The unified LAN + Wi-Fi headline, wrapped as a cell."""
    head = head or {}
    return Cell("Confirmed as yours",
                head.get("value") or "not read",
                sub=head.get("sub") or "",
                state=head.get("state") or UNKNOWN)


def strip(last_pass=None, admin=None, observations=None, machine_id="",
          inventory_head=None, now=None) -> List[Cell]:
    """The four cells, in reading order."""
    now = now or datetime.now(timezone.utc)
    return [patrol_cell(last_pass, now),
            alerting_cell(admin),
            witness_cell(observations, machine_id, now),
            inventory_cell(inventory_head)]


def worst(cells: Sequence[Cell]) -> str:
    """The strip's overall state. `unknown` outranks `ok` — never average.

    Averaging is how three greens and one blind spot become "mostly fine".
    """
    states = {c.state for c in cells}
    for state in (ATTENTION, UNKNOWN, OK):
        if state in states:
            return state
    return UNKNOWN
