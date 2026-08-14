"""Which machine owns this data directory — and refusing to let another write.

**This module exists because of a real incident, 2026-07-27.** A second
process on a different machine had the platform's folder mounted and ran
`patrol` and `corroborate` against it. Every write is stamped with
`hostname()`, so that process wrote its own hostname into the operator's
live state. The result:

- a **phantom second witness** — an observation file for a machine that was
  not on the LAN at all, with an empty neighbour table. `corroborate` duly
  reported "2 hosts witnessing" and produced findings comparing a real
  network against nothing.
- **132 of 137 guard-journal entries** belonged to the other machine. Only 5
  were the operator's. `timeline`, `digest` and the persistent-anomaly
  escalation all read that journal.
- 11 of 25 findings, a device row, an alert-log line.

Nothing raised. Nothing looked wrong. A corrupted history is *indis-
tinguishable* from a real one once written, because the records are the
only evidence of what happened, and both sets were well-formed. The only
tell was the machine name, and by then the damage was recorded as fact.

**This is not an exotic accident.** The same thing happens when a data
folder is on a synced volume, restored onto a different machine, or shared
between a host and a VM. Anywhere two machines can see one `data/`
directory, both will write to it, and the tool will believe all of it.

So the directory is **claimed** by the first machine to use it, and another
machine is refused rather than trusted. Refusing is the right severity:
a warning would be read once and then scrolled past for a month, and the
damage accumulates silently in the meantime.

**What is deliberately NOT covered:** `data/census/observations/`. That
folder is multi-machine *by design* — it is how a second witness reports —
and it has its own setting, `HUGINN_OBSERVATIONS_DIR`, precisely so it can
live somewhere shared while this directory does not. A second machine gets
its own checkout and its own data directory, and shares only observations.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

#: `HUGINN_OWNER_FILE` redirects the claim, which is how the tests exercise
#: the guard without staking a claim on the real directory. That is not a
#: hypothetical tidiness: the first run of the suite after this guard was
#: written claimed the operator's live folder for the test machine, which
#: would have locked him out of his own tool on the next verb. A guard whose
#: own tests can trigger the thing it guards against is not finished.
_DEFAULT_OWNER_PATH = os.path.join("data", "OWNER.json")
OWNER_PATH = _DEFAULT_OWNER_PATH


def owner_path() -> str:
    """Resolved at CALL time, not import time.

    Read once at import, a test that sets the variable after importing this
    module would silently write to the real directory — which is precisely
    the failure this indirection exists to prevent, so it must not depend on
    import order to work.
    """
    return (os.environ.get("HUGINN_OWNER_FILE", "").strip()
            or _DEFAULT_OWNER_PATH)

#: The one verb allowed to run on a foreign directory, because it is the
#: documented way out. Everything else writes something.
ALWAYS_ALLOWED = ("adopt",)

UNCLAIMED = "unclaimed"
OWNED = "owned"
FOREIGN = "foreign"


def read_owner(path: Optional[str] = None) -> Optional[dict]:
    """The claim on this directory, or None. A corrupt file counts as none.

    Failing to None rather than raising is deliberate: an unreadable claim
    must not be able to lock the operator out of their own tool. The cost of
    that choice is that a *deleted* claim silently re-claims on next use,
    which is the milder failure of the two.
    """
    path = path or owner_path()
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("machine_id") else None


def write_owner(machine_id: str, path: Optional[str] = None,
                note: str = "") -> bool:
    """Claim this directory for `machine_id`. Best-effort, never fatal."""
    path = path or owner_path()
    record = {
        "machine_id": machine_id,
        "claimed_at": datetime.now(timezone.utc).isoformat(),
        "note": note or ("Written by Huginn on first use. If another machine "
                         "runs against this folder, its records would mix "
                         "with these and both would look equally real."),
    }
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def state(record: Optional[dict], machine_id: str) -> str:
    """Pure: unclaimed / owned / foreign. No disk, no clock."""
    if not record or not record.get("machine_id"):
        return UNCLAIMED
    return OWNED if record["machine_id"] == machine_id else FOREIGN


def refusal(record: dict, machine_id: str, verb: str = "") -> str:
    """What to tell someone whose machine does not own this directory.

    Names both ways out, because a guard that only says "no" gets disabled.
    """
    owner = record.get("machine_id", "another machine")
    claimed = (record.get("claimed_at") or "")[:19].replace("T", " ")
    return (
        f"  REFUSED — this data directory belongs to \"{owner}\".\n"
        f"  {'=' * 58}\n"
        f"  This machine is \"{machine_id}\". Claimed {claimed} UTC.\n"
        f"\n"
        f"  Nothing was run{' (' + verb + ')' if verb else ''}, and nothing\n"
        f"  was written. Two machines writing one data directory mix their\n"
        f"  baselines, journals and findings into records that all look\n"
        f"  equally real afterwards — there is no way to tell them apart\n"
        f"  later except by machine name, and by then they are history.\n"
        f"\n"
        f"  If this machine is a SECOND WITNESS, it needs its own data\n"
        f"  directory and should share only the observations folder:\n"
        f"\n"
        f"      export HUGINN_OBSERVATIONS_DIR=/path/to/shared/folder\n"
        f"\n"
        f"  and run from its own checkout. See docs/SECOND-WITNESS.md.\n"
        f"\n"
        f"  If this machine has genuinely REPLACED \"{owner}\" (renamed,\n"
        f"  restored from backup, new hardware), take the directory over\n"
        f"  deliberately:\n"
        f"\n"
        f"      ./ops adopt                  (Linux, macOS)\n"
        f"      python tools\\ops.py adopt    (Windows)\n"
        f"\n"
        f"  Read what `adopt` says before running it: the baselines here\n"
        f"  were built by a different machine's view of the network."
    )


def guard(machine_id: str, verb: str = "",
          path: Optional[str] = None) -> Optional[str]:
    """None if this machine may write here; otherwise the refusal to print.

    Claims an unclaimed directory as a side effect — the first machine to
    use a fresh checkout is its owner, and asking about it would be a prompt
    nobody has the context to answer on day one.
    """
    path = path or owner_path()
    if verb in ALWAYS_ALLOWED:
        return None
    record = read_owner(path)
    status = state(record, machine_id)
    if status == UNCLAIMED:
        write_owner(machine_id, path)
        return None
    if status == OWNED:
        return None
    return refusal(record, machine_id, verb)


def adopt(machine_id: str, path: Optional[str] = None) -> str:
    """Transfer ownership to this machine, and say what that does not fix."""
    path = path or owner_path()
    previous = read_owner(path) or {}
    was = previous.get("machine_id", "(unclaimed)")
    if was == machine_id:
        return f"  This directory already belongs to \"{machine_id}\". Nothing changed."
    if not write_owner(machine_id, path, note=f"Adopted from {was}."):
        return "  Could NOT write the claim. Nothing changed."
    return (
        f"  This data directory now belongs to \"{machine_id}\" "
        f"(was \"{was}\").\n"
        f"\n"
        f"  ⚠ THE RECORDS IN IT ARE STILL THE OTHER MACHINE'S. Ownership\n"
        f"    is a lock, not a repair. Specifically:\n"
        f"\n"
        f"    - the LAN baseline lists devices as another host saw them, so\n"
        f"      the first census here may report ordinary devices as NEW,\n"
        f"      and may stay quiet about ones it should flag.\n"
        f"    - the guard journal, and therefore `timeline`, `digest` and\n"
        f"      the persistent-anomaly escalation, describe that host's\n"
        f"      network.\n"
        f"    - confirmed Wi-Fi radios were confirmed from where that\n"
        f"      machine was standing.\n"
        f"\n"
        f"  If this machine replaced the old one on the SAME network, the\n"
        f"  records are close enough to keep. If it is a different network,\n"
        f"  archive data/ and start clean — a wrong baseline is worse than\n"
        f"  no baseline, because absence of a finding then reads as calm."
    )
