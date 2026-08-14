"""Survey this machine's own coverage, and record that a patrol happened.

Two halves of one fact, deliberately in one module: `record_pass` writes the
heartbeat, `survey` reads it back. Keeping the writer beside the reader is
the cheap way to stop them drifting into two shapes that no longer meet.

**Why a heartbeat exists at all.** The guard's journal records CHANGES. A
patrol that finds nothing writes nothing — correctly, or a quiet week would
be a wall of noise. But it means a patrol running every hour and a patrol
that stopped a week ago leave identical evidence: an empty journal. There
was no wrong green light, there was no light, and the eye reads that as
calm. So every pass now leaves a mark whether or not it found anything, and
the console can tell "quiet" from "not running" — which are the two states
this whole product exists to keep apart.

Everything here is best-effort. A survey that raised would take down the
console's front page, and a heartbeat that raised would turn a successful
patrol into a failed verb. Both fail to "unknown" instead, which the
readiness domain renders honestly rather than as health.
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

from agents.alerting import load_admin, redact
from agents.witnessing import read_observations
from domains import inventory as inv
from domains import readiness
from domains.census import load_baseline as load_lan_baseline
from domains.wifi import load_baseline as load_wifi_baseline
from engines.wifi_scan import is_available as wifi_available, read_radios
from platform_support import hostname

#: One small JSON file, overwritten each pass. Not a log: the question it
#: answers is "when did the guard last run", and a growing history of that
#: would be a second timeline nobody asked for.
HEARTBEAT_PATH = os.path.join("data", "census", "last_patrol.json")

LAN_BASELINE = os.path.join("data", "census", "lan_baseline.json")


def record_pass(machine_id: str, result=None, path: str = HEARTBEAT_PATH,
                now: Optional[str] = None) -> bool:
    """Mark that a patrol completed. Returns whether the mark was written.

    Records the pass's own verdict alongside the time, so the console can
    say "nothing above info" as a reading rather than as an assumption.
    """
    findings = list(getattr(result, "alert_findings", None) or [])
    payload = {
        "ts": now or datetime.now(timezone.utc).isoformat(),
        "machine": machine_id,
        "attention": len(findings),
        "alerted": bool(getattr(result, "should_alert", False)),
        "devices": int(getattr(result, "census_count", 0) or 0),
        "exposed": int(getattr(result, "exposed_count", 0) or 0),
    }
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp, path)
        return True
    except OSError:
        return False


def read_pass(path: str = HEARTBEAT_PATH) -> Optional[dict]:
    """The last recorded pass, or None. A corrupt file counts as none."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _radios():
    """The air, as (radios, readable). `None` radios means the read FAILED.

    A machine with no wireless hardware is reported unreadable rather than
    empty, because "no radio was checked" and "no radio was heard" are
    different claims and only one of them is an all-clear.
    """
    if not wifi_available():
        return None, False
    try:
        found = read_radios()
    except Exception:                       # noqa: BLE001 - never break the page
        return None, False
    return found, found is not None


def _lan():
    """The census baseline, as (baseline, readable)."""
    try:
        if not os.path.exists(LAN_BASELINE):
            return {}, False
        return load_lan_baseline(LAN_BASELINE), True
    except Exception:                       # noqa: BLE001
        return {}, False


def _admin():
    try:
        return redact(load_admin())
    except Exception:                       # noqa: BLE001
        return {}


def _observations():
    try:
        return read_observations()
    except Exception:                       # noqa: BLE001
        return []


def survey(machine_id: Optional[str] = None, now=None) -> dict:
    """Everything the console's front page needs, in one read.

    Read-only by construction: it opens baselines and one cached Wi-Fi scan,
    and writes nothing. That is what lets it sit on a GET, on a server with
    no authentication — it widens what can be *seen* from a port that could
    already run every verb, and nothing that can be *changed*.
    """
    machine_id = machine_id or hostname()
    lan_baseline, lan_ok = _lan()
    radios, wifi_ok = _radios()

    stock = inv.build(lan_baseline=lan_baseline, radios=radios,
                      wifi_baseline=load_wifi_baseline(),
                      lan_readable=lan_ok, wifi_readable=wifi_ok)
    cells = readiness.strip(
        last_pass=read_pass(), admin=_admin(),
        observations=_observations(), machine_id=machine_id,
        inventory_head=inv.headline(stock), now=now)

    return {
        "ok": True,
        "machine": machine_id,
        "state": readiness.worst(cells),
        "cells": [c.as_dict() for c in cells],
        "inventory": stock.as_dict(),
    }
