"""Evil-twin detection — a second radio answering for a network you trust.

Pure. Radios in, findings out.

**The naive rule is a noise machine, and the operator's own network proves
it.** "A known SSID on an unknown BSSID" sounds like an evil twin. His SSID
legitimately has SIX BSSIDs — three dual-band access points in a mesh, each
radio its own BSSID. That rule would have fired on his own kit every time it
was heard, which is precisely how an operator learns to ignore an alert.

So detection is against a **confirmed baseline of BSSIDs**, not against the
SSID alone. Four rules:

**1. Only a trusted SSID can have a twin.** A stranger's network appearing
on a new BSSID is a stranger's business. This looks only at SSIDs the
operator has said are theirs.

**2. A new BSSID for a trusted SSID is `warning` / `likely` — never
critical, never certain.** Buying a repeater produces exactly this signal.
The finding says what was seen and what would confirm it, and leaves the
verdict to the person who knows whether they bought a repeater.

**3. Security is compared WITHIN a band.** On his mesh, 2.4GHz is `WPA2` and
5GHz is `WPA2 WPA3` — legitimately. Comparing across bands would invent a
downgrade on every single AP. A weaker offering *on the same band as a
trusted radio* is the real signal, and it is the strongest one here: an
attacker wanting your credentials cannot offer WPA3 it does not have.

**4. Signal is context, never a trigger.** A rogue AP is often closer than
the real one, but so is a laptop carried into another room. Reported beside
the finding; never the reason for it.
"""

import json
import os
from typing import Dict, List, Optional, Sequence

from contracts import Finding
from contracts.finding import Coverage

#: Security tokens ordered weakest first. Anything unrecognised sorts
#: BELOW everything known: an unfamiliar scheme on a network you trust is
#: worth a look, and treating the unknown as strong would hide exactly the
#: case worth seeing.
_STRENGTH = {"": 0, "open": 0, "wep": 1, "wpa1": 2, "wpa": 2,
             "wpa2": 3, "wpa3": 4}


def security_rank(security: str) -> int:
    """Best scheme offered by this radio. Open/unknown ranks lowest.

    Matched as SUBSTRINGS, not tokens, because every platform words this
    differently and only the family name is common to all of them:

        Linux (nmcli)     "WPA2 WPA3"
        Windows (netsh)   "WPA2-Personal"      <- token match fails here
        macOS (airport)   "WPA2(PSK/AES/AES)"  <- and here

    Token matching ranked `WPA2-Personal` as ZERO — weakest — which would
    have inverted the downgrade signal on every Windows machine: real APs
    reported as insecure, a genuine open twin indistinguishable from them.
    """
    text = (security or "").lower()
    if not text.strip():
        return 0
    best = 0
    for name, rank in _STRENGTH.items():
        if name and name in text:
            best = max(best, rank)
    return best


def trusted_bssids(baseline: dict, ssid: str) -> set:
    return {b.upper() for b in (baseline.get(ssid) or [])}


def trusted_ssids(baseline: dict) -> set:
    return {s for s in (baseline or {}) if s}


def unknown_radios(radios: Sequence, baseline: dict) -> List:
    """Radios broadcasting a TRUSTED ssid from an UNTRUSTED bssid."""
    known = trusted_ssids(baseline)
    return [r for r in (radios or [])
            if r.ssid in known and r.bssid.upper() not in trusted_bssids(baseline, r.ssid)]


def _coverage(radios) -> Coverage:
    return Coverage(checked=len(radios or []), total=len(radios or []))


def _same_band_ranks(radios, baseline, ssid, band) -> List[int]:
    return [security_rank(r.security) for r in radios
            if r.ssid == ssid and r.band == band
            and r.bssid.upper() in trusted_bssids(baseline, ssid)]


def assess(radios: Optional[Sequence], baseline: dict,
           machine_id: str) -> List[Finding]:
    """Findings from one scan. `radios is None` means the scan failed."""
    if radios is None or not baseline:
        return []                           # see `unchecked` — never a pass

    findings: List[Finding] = []
    for radio in unknown_radios(radios, baseline):
        findings.append(_twin_finding(radio, radios, baseline, machine_id))
    return findings


def _twin_finding(radio, radios, baseline, machine_id: str) -> Finding:
    trusted_here = _same_band_ranks(radios, baseline, radio.ssid, radio.band)
    mine = security_rank(radio.security)
    downgraded = bool(trusted_here) and mine < max(trusted_here)

    message = (f"A radio you have not confirmed is broadcasting "
               f"\"{radio.ssid}\": {radio.bssid} on {radio.band} "
               f"ch{radio.channel}, signal {radio.signal}")
    if downgraded:
        message += (f". It offers weaker security ({radio.security or 'open'}) "
                    f"than your confirmed radios on the same band")

    action = (f"If you added an access point or repeater, confirm it: "
              f"`wifi trust {radio.bssid}`. If you did not, this is what an "
              f"evil twin looks like — check the MAC against the label on "
              f"your own equipment before connecting to it again.")
    if downgraded:
        action = ("An attacker cannot offer security they do not have, so a "
                  "WEAKER option on your own SSID is the stronger signal. "
                  + action)

    return Finding(
        id=f"wifi_unconfirmed_bssid_{radio.bssid.replace(':', '')}",
        source_module="lan-poison",
        machine_id=machine_id,
        severity="warning",
        confidence="likely",
        message=message + ".",
        coverage=_coverage(radios),
        suggested_action=action,
        tags=("security", "wifi"),
    )


def unchecked(radios: Optional[Sequence], baseline: dict) -> List[str]:
    """What could NOT be judged, so absence is never read as safety."""
    reasons = []
    if radios is None:
        reasons.append("the Wi-Fi scan could not be read — no radio was "
                       "checked, which is not the same as no rogue AP")
    elif not baseline:
        reasons.append("no confirmed radios yet, so nothing can be called "
                       "unexpected — run `wifi trust` first")
    return reasons


def learn(radios: Optional[Sequence], baseline: dict,
          ssid: Optional[str] = None) -> dict:
    """Add currently-visible BSSIDs to the baseline.

    **Whatever is in earshot right now becomes trusted**, which is the whole
    risk of learning a baseline: an evil twin already running is trusted
    forever. The verb says so out loud and tells the operator to check the
    MACs against their own equipment. A quiet auto-baseline would bury that.
    """
    updated = {key: list(value) for key, value in (baseline or {}).items()}
    for radio in radios or []:
        if radio.hidden:
            continue                        # a nameless radio cannot be "yours"
        if ssid and radio.ssid != ssid:
            continue
        known = updated.setdefault(radio.ssid, [])
        if radio.bssid.upper() not in {b.upper() for b in known}:
            known.append(radio.bssid.upper())
    return updated


def forget(baseline: dict, bssid: str) -> dict:
    """Remove one BSSID from every SSID that trusts it."""
    target = (bssid or "").upper()
    return {ssid: [b for b in bssids if b.upper() != target]
            for ssid, bssids in (baseline or {}).items()}


# --- the confirmed list, on disk -------------------------------------------
#
# Lives here rather than in the skill because BOTH `wifi` and `patrol` read
# it, and platform skills must never import one another — that collision
# was a live outage once. Same shape as domains/census.load_baseline.

BASELINE_PATH = os.path.join("data", "census", "wifi_baseline.json")


def load_baseline(path: str = BASELINE_PATH) -> dict:
    """The confirmed radios. A missing or corrupt file means none."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_baseline(baseline: dict, path: str = BASELINE_PATH) -> bool:
    """Write via a temp file, so a reader never sees a half-written list."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(baseline, handle, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
        return True
    except OSError:
        return False
