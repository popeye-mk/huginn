"""Symptom-driven triage (spec §7).

`diag why slow` runs a subset of collectors relevant to a complaint and
promotes the rules most likely to explain it. Two deliberate limits:

1. Narrowing the collector set *increases* what lands in "Not checked" —
   it never shrinks it silently. Every core collector the profile
   skipped is reported as `not_run_for_symptom` so a narrowed run can
   never read as a clean bill of health (§3.4). This is the whole
   reason triage is safe to ship: a faster answer that hides its own
   scope is worse than a slow one.

2. Weighting is display-only. It reorders findings; it cannot create,
   suppress, or upgrade one. Exit codes are computed from the same flat
   finding list as `diag run` (§16).
"""

import os

import yaml

from resources import resource_path

TRIAGE_PATH = resource_path("pattern_kb", "triage.yaml")


def load_profiles(path=TRIAGE_PATH):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def get_profile(symptom, profiles=None):
    """Returns the matching profile, or None -> caller falls back to a full run."""
    profiles = profiles if profiles is not None else load_profiles()
    for profile in profiles:
        if profile["symptom"] == symptom:
            return profile
    return None


def known_symptoms(profiles=None):
    profiles = profiles if profiles is not None else load_profiles()
    return sorted(p["symptom"] for p in profiles)


def select_collectors(profile, available):
    """Filter `available` (name, func, timeout, privilege) tuples to the profile.

    Order is preserved from `available`, not from the profile, so the
    run order stays stable and predictable across symptoms.
    """
    wanted = set(profile["collectors"])
    return [entry for entry in available if entry[0] in wanted]


def excluded_collectors(profile, available):
    """Collector ids deliberately not run for this symptom.

    These are merged into the report's "Not checked" list by the caller.
    They are not failures — but they are also not health, and the
    report must say so out loud (§3.4).
    """
    wanted = set(profile["collectors"])
    return [entry[0] for entry in available if entry[0] not in wanted]


def prioritise(findings, profile):
    """Stable-sort findings so profile-weighted ids lead, severity within.

    Display-only (§16): same list, same length, different order.
    """
    weight = {rule_id: i for i, rule_id in enumerate(profile.get("weight", []))}
    severity_order = {"critical": 0, "warning": 1}
    return sorted(
        findings,
        key=lambda f: (
            weight.get(f["id"], len(weight)),
            severity_order.get(f["severity"], 9),
        ),
    )
