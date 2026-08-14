"""What is on this network, and which of it a human has actually confirmed.

Pure. Baselines and sightings in, one flat list of `Item` out.

**Why one list rather than two panels.** A LAN device and a Wi-Fi radio look
like different subjects — one is a MAC on a wire, the other a BSSID in the
air — but the operator asks them the same question, in the same voice, at
the same moment: *is that thing mine?* Splitting that question across two
screens with two vocabularies ("baseline" here, "trusted" there) means the
answer has to be reassembled in the operator's head every time. So both
kinds become the same shape, and a third kind (a witnessing machine, a
device on a second segment) can join without a third vocabulary.

**The distinction this module exists to make: SEEN is not CONFIRMED.**

The census baseline learns every device it meets. That is correct — it is a
memory of what has been here, and it is what makes "a device appeared
overnight" answerable at all. But it records only that a thing was *seen*.
Nobody ever said it was theirs.

Read as a safety signal, that baseline is empty: eleven devices in it and
zero labelled is not eleven confirmed devices, it is eleven devices nobody
has ever named — and the one that does not belong is sitting in the same
undifferentiated list as the printer. `confirmed` here means a human acted:
a `label` on a LAN device, a BSSID in the Wi-Fi baseline. Nothing is
confirmed by having been tolerated.

Wi-Fi already worked this way, because a mesh forced the issue. LAN did
not, and the gap was invisible while the two lists lived apart.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

LAN = "lan"
WIFI = "wifi"


@dataclass(frozen=True)
class Item:
    """One thing on the network, of either kind.

    `confirmed` is a claim about a PERSON, not about the thing: someone
    looked at this and said it was theirs. `present` is a claim about the
    last read: it answers "is it here now", and the two are independent —
    a confirmed access point in a far room is absent and fine, an
    unconfirmed device that is present is the question worth asking.
    """

    kind: str
    key: str
    name: str
    detail: str = ""
    confirmed: bool = False
    present: bool = True
    note: str = ""
    confirm_with: str = ""

    def as_dict(self) -> dict:
        return {"kind": self.kind, "key": self.key, "name": self.name,
                "detail": self.detail, "confirmed": self.confirmed,
                "present": self.present, "note": self.note,
                "confirm_with": self.confirm_with}


@dataclass(frozen=True)
class Inventory:
    """The whole picture, including what could NOT be read.

    `unreadable` is a first-class field rather than an empty list, because
    an inventory that cannot see the air and an inventory that saw nothing
    unexpected produce the same count and mean opposite things.
    """

    items: List[Item] = field(default_factory=list)
    unreadable: List[str] = field(default_factory=list)
    ignored: int = 0
    #: When the census last swept. `present` is a claim as of THIS moment,
    #: not as of now — without it a baseline that stopped being updated
    #: would keep reporting a room full of devices as "here", which is the
    #: same stale-reading-as-fact mistake in miniature.
    as_of: str = ""

    def of_kind(self, kind: str) -> List[Item]:
        return [i for i in self.items if i.kind == kind]

    def as_dict(self) -> dict:
        return {"items": [i.as_dict() for i in self.items],
                "unreadable": list(self.unreadable),
                "ignored": self.ignored,
                "as_of": self.as_of,
                "counts": counts(self)}


def counts(inventory: Inventory) -> dict:
    """Totals for the status strip. `unreadable` is carried, never folded in."""
    items = inventory.items
    return {
        "total": len(items),
        "confirmed": len([i for i in items if i.confirmed]),
        "unconfirmed": len([i for i in items if not i.confirmed]),
        "unconfirmed_present": len(
            [i for i in items if not i.confirmed and i.present]),
        "unreadable": len(inventory.unreadable),
    }


# --- LAN -------------------------------------------------------------------

def _last_sweep(baseline: dict) -> str:
    """When the census last ran, read off the records themselves.

    `census_diff` stamps every device it touches with a single `now`, so the
    newest `last_seen` in the file IS the last sweep. Deriving it beats
    storing it: a separate field could drift from the records it describes.
    """
    return max((rec.get("last_seen") or "" for rec in baseline.values()),
               default="")


def lan_items(baseline: Optional[dict]) -> List[Item]:
    """Every device the census remembers, marked confirmed only if LABELLED.

    A probed hostname (`name`) deliberately does not count. It is what the
    device says about itself, and a device on your network that you cannot
    account for is exactly the one whose self-description you should not be
    taking as identification.
    """
    baseline = baseline or {}
    sweep = _last_sweep(baseline)
    items = []
    for mac, rec in sorted(baseline.items(), key=lambda kv: kv[1].get("ip", "")):
        label = (rec.get("label") or "").strip()
        probed = (rec.get("name") or "").strip()
        vendor = (rec.get("vendor") or "").strip()
        ip = rec.get("ip") or ""
        detail = " · ".join(x for x in (ip, vendor) if x)
        note = "" if label else (f"answers to \"{probed}\"" if probed else "")
        items.append(Item(
            kind=LAN, key=mac, name=label or probed or vendor or mac,
            detail=detail, confirmed=bool(label),
            present=bool(sweep) and rec.get("last_seen") == sweep,
            note=note,
            confirm_with=f"label {ip} " if ip else "",
        ))
    return items


# --- Wi-Fi -----------------------------------------------------------------

def _candidate_ssids(radios: Sequence, baseline: dict) -> set:
    """Which SSIDs this list is about.

    Normally: the ones already confirmed. With an EMPTY baseline there are
    none, and the panel would be blank on exactly the machine that has never
    confirmed anything — so the network currently associated is offered as
    the starting point. That is the same bootstrap `wifi trust` performs,
    and it carries the same warning: whatever is in earshot when you first
    confirm is what you are confirming.
    """
    known = {s for s in (baseline or {}) if s}
    if known:
        return known
    return {r.ssid for r in (radios or []) if getattr(r, "in_use", False) and r.ssid}


def wifi_items(radios: Optional[Sequence], baseline: Optional[dict]) -> List[Item]:
    """Radios serving YOUR networks, plus confirmed ones not currently heard.

    A neighbour's access point is not listed. It is not evidence about your
    network, and a list padded with thirteen radios you have no opinion
    about is a list nobody reads to the bottom.
    """
    baseline = baseline or {}
    radios = list(radios or [])
    mine = _candidate_ssids(radios, baseline)
    trusted = {ssid: {b.upper() for b in bssids}
               for ssid, bssids in baseline.items()}

    items, heard = [], set()
    for radio in sorted(radios, key=lambda r: (-r.signal, r.ssid)):
        if radio.ssid not in mine or radio.hidden:
            continue
        key = radio.bssid.upper()
        heard.add((radio.ssid, key))
        bits = [radio.band, f"ch{radio.channel}", f"signal {radio.signal}",
                radio.security or "open"]
        items.append(Item(
            kind=WIFI, key=key, name=radio.ssid, detail=" · ".join(bits),
            confirmed=key in trusted.get(radio.ssid, set()),
            present=True, note="connected" if radio.in_use else "",
            confirm_with=f"wifi trust {key}",
        ))

    for ssid, bssids in trusted.items():
        for bssid in sorted(bssids):
            if (ssid, bssid) in heard:
                continue
            items.append(Item(
                kind=WIFI, key=bssid, name=ssid, detail="not heard from here",
                confirmed=True, present=False, note="out of earshot",
                confirm_with=f"wifi forget {bssid}",
            ))
    return items


def ignored_radios(radios: Optional[Sequence], baseline: Optional[dict]) -> int:
    """How many radios were heard and deliberately left out.

    Shown to the operator so the omission is a stated decision rather than
    something the panel quietly did.
    """
    radios = list(radios or [])
    mine = _candidate_ssids(radios, baseline or {})
    return len([r for r in radios if r.ssid not in mine or r.hidden])


# --- assembly --------------------------------------------------------------

def build(lan_baseline: Optional[dict] = None,
          radios: Optional[Sequence] = None,
          wifi_baseline: Optional[dict] = None,
          lan_readable: bool = True,
          wifi_readable: bool = True) -> Inventory:
    """One inventory from both sources, carrying what could not be read.

    `radios is None` and `radios == []` are different facts and are kept
    different: the first is a failed scan, the second is a machine with the
    radio off or nothing in range. Only the caller knows which, so it says
    so with `wifi_readable` rather than this module inferring it.
    """
    items: List[Item] = []
    unreadable: List[str] = []

    if lan_readable:
        items += lan_items(lan_baseline)
    else:
        unreadable.append("the LAN baseline could not be read — no device "
                          "was checked, which is not the same as no stranger")

    if wifi_readable and radios is not None:
        items += wifi_items(radios, wifi_baseline)
    else:
        unreadable.append("the Wi-Fi scan could not be read — no radio was "
                          "checked, which is not the same as no evil twin")

    return Inventory(items=items, unreadable=unreadable,
                     as_of=_last_sweep(lan_baseline or {}),
                     ignored=ignored_radios(radios, wifi_baseline)
                     if wifi_readable and radios is not None else 0)


def headline(inventory: Inventory) -> Dict[str, str]:
    """One sentence for the status strip, and the state it should wear.

    Never green while something is unreadable: a clean count over a partial
    read is the exact shape of a false all-clear.
    """
    tally = counts(inventory)
    if inventory.unreadable:
        return {"state": "unknown", "value": "partly unread",
                "sub": inventory.unreadable[0]}
    if not tally["total"]:
        return {"state": "unknown", "value": "nothing recorded",
                "sub": "run a census and a Wi-Fi scan before reading this"}
    if not tally["unconfirmed"]:
        return {"state": "ok", "value": f"all {tally['total']} confirmed",
                "sub": "every device and radio has been named by you"}
    here = tally["unconfirmed_present"]
    return {"state": "attention",
            "value": f"{tally['unconfirmed']} unconfirmed",
            "sub": (f"{here} of them here now · "
                    f"{tally['confirmed']} of {tally['total']} named")}
