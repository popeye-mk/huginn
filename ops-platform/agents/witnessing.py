"""Writing and reading observations — the second-witness transport.

Named `witnessing` rather than `observing` because `agents/observing.py`
already exists and means something else (this host's own connections, for
the `threat` verb). Different job, different word: that one observes THIS
machine, this one collects what OTHER machines witnessed.

**There is no network protocol here, and that is the design.** A host
writes a small JSON file describing what it just saw; any host that can
read that file gains a second witness. Nothing listens, nothing is accepted
from the network, and Huginn's loopback-only property is untouched.

How the file travels between machines is the operator's choice and
deliberately outside this code — a synced folder, an SMB share, a USB
stick, `scp` from a scheduled job. Building a transport would mean building
a listener, and a security tool that opens a port in order to improve its
security posture has made a trade nobody asked for.

The cost is stated rather than hidden: **a shared folder is a shared trust
boundary.** Anything that can write into it can hand this host a fabricated
observation. Corroboration therefore RAISES confidence; it never
establishes truth, and `domains/corroboration` words every finding that way.
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Optional

from contracts.observation import Observation
from engines.lan_anomaly import read_dhcp_server, read_gateway
from engines.lan_census import LanCensusEngine, raw_pairs
from engines.lan_sweep import local_networks
from platform_support import hostname

#: Where this host writes its own observation, and reads everyone's.
#:
#: `HUGINN_OBSERVATIONS_DIR` overrides it, which is how two machines end up
#: sharing one folder without either of them editing code. Set it on both to
#: the same synced/mounted path and they corroborate; leave it unset and
#: `corroborate` says plainly that there is only one witness.
#:
#: An env var rather than a config key on purpose: the scheduled runners
#: (systemd unit, Windows task) already carry environment, and a witness
#: directory that only worked when a human ran the verb by hand would be a
#: witness that goes stale exactly when nobody is looking.
_DEFAULT_OBSERVATION_DIR = os.path.join("data", "census", "observations")
OBSERVATION_DIR = os.environ.get("HUGINN_OBSERVATIONS_DIR", "").strip() \
    or _DEFAULT_OBSERVATION_DIR


def observation_dir() -> str:
    """The live directory, re-read from the environment on every call.

    Module-level constants are captured at import; a long-running server
    would never notice the variable changing. Callers that want the current
    answer ask for it.
    """
    return os.environ.get("HUGINN_OBSERVATIONS_DIR", "").strip() \
        or _DEFAULT_OBSERVATION_DIR


def _safe(fn, *args):
    try:
        return fn(*args)
    except Exception:                       # noqa: BLE001
        return None


def observe(machine_id: Optional[str] = None,
            now: Optional[datetime] = None) -> Observation:
    """Read this host's view of the segment. Never raises.

    `readable=False` when the neighbour table could not be read at all,
    which must never be confused with an empty table. A host that cannot
    see is not a host that sees nothing — the same distinction the rest of
    this platform is built on, carried into the record other machines will
    trust.
    """
    machine_id = machine_id or hostname()
    now = now or datetime.now(timezone.utc)

    neighbours, readable = {}, False
    engine = LanCensusEngine()
    if _safe(engine.is_available):
        raw = _safe(lambda: str(engine.run().payload or ""))
        if raw is not None:
            sightings = _safe(raw_pairs, raw)
            if sightings is not None:
                readable = True
                neighbours = {s.ip: s.mac for s in sightings if s.ip and s.mac}

    gateway_ip = _safe(read_gateway)
    return Observation(
        machine_id=machine_id,
        observed_at=now.isoformat(timespec="seconds"),
        gateway_ip=gateway_ip,
        gateway_mac=neighbours.get(gateway_ip) if gateway_ip else None,
        dhcp_server=_safe(read_dhcp_server),
        neighbours=neighbours,
        local_networks=[str(n) for n in (_safe(local_networks) or [])],
        readable=readable,
    )


def write_observation(observation: Observation,
                      directory: Optional[str] = None) -> str:
    """Write this host's observation, replacing its previous one.

    One file per machine, overwritten — not a history. The guard timeline
    already keeps history; what corroboration needs is each witness's
    CURRENT statement, and a directory that accumulated every pass would
    turn "the newest from each host" into a search rather than a read.

    Written via a temp file and `os.replace`, so a reader on a synced folder
    can never catch a half-written record and treat the missing half as a
    network that changed.
    """
    directory = directory or observation_dir()
    os.makedirs(directory, exist_ok=True)
    safe_name = "".join(c if (c.isalnum() or c in "-_") else "_"
                        for c in observation.machine_id)[:60] or "unknown"
    path = os.path.join(directory, f"observation-{safe_name}.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(observation.to_dict(), handle, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return path


def read_observations(directory: Optional[str] = None) -> List[Observation]:
    """Every observation in the directory. A bad file is skipped, not fatal.

    One unreadable file from one host must not deny the operator the
    witnesses that ARE readable.
    """
    directory = directory or observation_dir()
    out: List[Observation] = []
    try:
        names = sorted(os.listdir(directory))
    except OSError:
        return out
    for name in names:
        if not (name.startswith("observation-") and name.endswith(".json")):
            continue
        try:
            with open(os.path.join(directory, name), encoding="utf-8") as handle:
                out.append(Observation.from_dict(json.load(handle)))
        except (OSError, ValueError):
            continue
    return out


def record(machine_id: Optional[str] = None,
           directory: Optional[str] = None) -> str:
    """Observe and write in one call. Returns the path, or "" on failure."""
    try:
        return write_observation(observe(machine_id), directory)
    except OSError:
        return ""
