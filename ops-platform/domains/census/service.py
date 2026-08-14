"""LAN census domain — the meaning layer for G1.

The engine says what is on the segment right now. This says what
*changed* since last time, because a device list is only interesting
against a baseline: a device that has always been there is furniture; a
device that appeared overnight is the question the guard exists to raise.

Three findings, and the severity of each is a deliberate claim:

- **A new MAC** is a `warning` — something joined the network. Not
  proof of anything, but the operator should know a device they may not
  recognise is present. Tagged `security`/`lan`.
- **A MAC↔IP change** (a known device now answering on a different IP, or
  an IP now claimed by a different MAC) is a `warning` too — it is the
  fingerprint of ARP spoofing / a MITM attempt, and also of ordinary DHCP
  churn, so it is flagged for a human to judge, never auto-actioned.
- **A vanished device** is `info` — it left. Worth recording, rarely
  worth alarm.

Absence discipline, inherited from triage: an empty run (nothing in the
cache) is not "the LAN is clear" — it is "nothing was seen," and the
coverage on the findings says so.
"""

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

from contracts.finding import Coverage, Finding


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CensusResult:
    """The outcome of one census: findings + the baseline to persist."""

    findings: List[Finding]
    baseline: Dict[str, dict]
    seen: int
    new_baseline_created: bool = False
    devices: List[dict] = field(default_factory=list)


def _finding(fid, machine_id, severity, message, action, seen, plain=None):
    return Finding(
        id=fid,
        source_module="lan-census",
        machine_id=machine_id,
        severity=severity,
        confidence="certain",
        message=message,
        coverage=Coverage(checked=seen, total=seen),
        suggested_action=action,
        plain_message=plain,
        tags=("security", "lan"),
    )


def _new_device_finding(s, machine_id, seen) -> Finding:
    vend = s.vendor or "unknown vendor"
    label = f"{s.ip} ({s.mac}{', ' + s.vendor if s.vendor else ''})"
    return _finding(
        f"lan_new_device_{s.mac}", machine_id, "warning",
        f"New device on the LAN: {label}",
        "Confirm you recognise this device; if not, find its switch port "
        "and investigate.", seen,
        plain=(f"A device you have not seen before joined the network "
               f"({vend}). If it is not yours, someone else is on your LAN."),
    )


def _ip_change_finding(s, prior, machine_id, seen) -> Finding:
    return _finding(
        f"lan_ip_change_{s.mac}", machine_id, "warning",
        f"Known device changed IP: {s.mac} {prior.get('ip')} -> {s.ip}",
        "Usually DHCP churn; if unexpected, check for ARP spoofing (a "
        "device impersonating another).", seen,
        plain=("A device you know is now using a different address. Normal "
               "after a lease renewal — but it is also what an "
               "address-hijack looks like."),
    )


def _apply_sighting(s, baseline, machine_id, seen, first_run, now) -> List[Finding]:
    """Update the baseline for one sighting; return any findings it raises."""
    prior = baseline.get(s.mac)
    if prior is None:
        # First run: everything is 'new' — that's the baseline forming, not
        # an alert storm, so record without a finding.
        found = [] if first_run else [_new_device_finding(s, machine_id, seen)]
        baseline[s.mac] = {"ip": s.ip, "vendor": s.vendor,
                           "name": getattr(s, "name", ""),
                           "first_seen": now, "last_seen": now}
        return found
    found = []
    if prior.get("ip") != s.ip:
        found.append(_ip_change_finding(s, prior, machine_id, seen))
    prior["ip"] = s.ip
    prior["last_seen"] = now
    if s.vendor:
        prior["vendor"] = s.vendor
    name = getattr(s, "name", "")
    if name:
        prior["name"] = name          # a probed name updates the record
    return found


def set_label(baseline, ip: str, label: str):
    """Pin (or clear) a manual friendly label on the device now at `ip` (G1f).

    The label is stored against the device's MAC, not its IP, so it follows
    the device across DHCP lease changes. It is a *separate* field from the
    probed `name` (G1e): a re-scan updates `name` but never touches `label`,
    so a hand-given label survives every future census. An empty/blank label
    clears it. Returns the MAC labelled, or None when no device in the
    baseline currently answers on that IP (caller degrades honestly — you
    cannot label a device the census has never seen).
    """
    for mac, rec in (baseline or {}).items():
        if rec.get("ip") == ip:
            label = (label or "").strip()
            if label:
                rec["label"] = label
            else:
                rec.pop("label", None)
            return mac
    return None


def effective_name(rec: dict) -> str:
    """The name to show for a device: a manual label wins over a probed
    name wins over nothing. Vendor is deliberately not folded in here —
    callers that want a vendor fallback add it themselves."""
    rec = rec or {}
    return rec.get("label") or rec.get("name") or ""


def census_diff(sightings, baseline, machine_id) -> CensusResult:
    """Compare current sightings to the baseline and produce findings.

    `sightings` are engine `Sighting` objects; `baseline` maps
    mac -> {ip, vendor, name, label, first_seen, last_seen}. Returns findings
    plus the updated baseline to save.
    """
    baseline = dict(baseline or {})
    first_run = not baseline
    now = _now()
    seen = len(sightings)
    findings: List[Finding] = []
    devices = [s.as_dict() for s in sightings]
    current_macs = {s.mac for s in sightings}

    for s in sightings:
        findings += _apply_sighting(s, baseline, machine_id, seen, first_run, now)

    if not first_run:
        for mac, rec in list(baseline.items()):
            if mac not in current_macs:
                findings.append(_finding(
                    f"lan_gone_{mac}", machine_id, "info",
                    f"Device no longer seen: {mac} (last at {rec.get('ip')})",
                    "No action needed unless you expected it online.", seen,
                ))

    # Carry any manual label (G1f) from the baseline onto the device rows so
    # the render and dashboard can prefer it over the probed name.
    for d in devices:
        rec = baseline.get(d.get("mac"))
        if rec and rec.get("label"):
            d["label"] = rec["label"]

    return CensusResult(findings=findings, baseline=baseline, seen=seen,
                        new_baseline_created=first_run, devices=devices)


# --- baseline persistence (a plain JSON file; state, not content) ---------

def load_baseline(path: str) -> Dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_baseline(path: str, baseline: Dict[str, dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=1, ensure_ascii=False)
    os.replace(tmp, path)
