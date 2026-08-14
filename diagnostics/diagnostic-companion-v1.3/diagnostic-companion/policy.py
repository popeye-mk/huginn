"""Policy & compliance baseline (spec §9).

Evaluates a snapshot against a declarative YAML policy. Deliberately
reuses the interpreter's dot-path resolution so there is exactly one
place in the codebase that knows how to read a value out of a snapshot.

Three outcomes, not two:

  pass    — the rule was checked and satisfied
  fail    — the rule was checked and violated
  unknown — the collector the rule depends on did not produce data

`unknown` is the entire reason this module is defensible (§9). Turning
"I could not check whether disks are encrypted" into "compliant" is how
compliance reports become actively harmful. Unknowns are counted and
listed separately, never folded into either the pass or the fail bucket.
"""

import os

import yaml

from resources import resource_path

from interpreter import MISSING, _get_by_path, _section_status

POLICY_DIR = resource_path("policy")
DEFAULT_POLICY = os.path.join(POLICY_DIR, "kmo-default.yaml")

POLICY_OPS = {
    "at_least": lambda actual, value: actual is not None and actual >= value,
    "at_most": lambda actual, value: actual is not None and actual <= value,
    "equals": lambda actual, value: actual == value,
}


def load_policy(path=DEFAULT_POLICY):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def check(snapshot, policy=None):
    """Returns a list of {rule, description, severity, outcome, detail}."""
    policy = policy if policy is not None else load_policy()
    results = []

    for entry in policy:
        match = entry["match"]
        status = _section_status(snapshot, match["path"])

        if status != "ok":
            reason = "collector not present in snapshot"
            collector_id = match["path"].split(".")[0]
            section = snapshot.get("sections", {}).get(collector_id)
            if section:
                reason = f"{section['status']}: {section['reason']}"
            results.append({
                "rule": entry["rule"],
                "description": entry["description"],
                "severity": entry["severity"],
                "outcome": "unknown",
                "detail": reason,
            })
            continue

        actual = _get_by_path(snapshot, "sections." + match["path"])
        if actual is MISSING:
            # The collector ran but this snapshot has no such field —
            # an older schema, or a field the OS does not expose.
            # Unknown, never pass (§9).
            results.append({
                "rule": entry["rule"],
                "description": entry["description"],
                "severity": entry["severity"],
                "outcome": "unknown",
                "detail": f"{match['path']} not present in this snapshot",
            })
            continue

        satisfied = POLICY_OPS[match["op"]](actual, match["value"])
        results.append({
            "rule": entry["rule"],
            "description": entry["description"],
            "severity": entry["severity"],
            "outcome": "pass" if satisfied else "fail",
            "detail": f"{match['path']} = {actual} (required {match['op']} {match['value']})",
        })

    return results


def summarise(results):
    counts = {"pass": 0, "fail": 0, "unknown": 0}
    for r in results:
        counts[r["outcome"]] += 1
    return counts


def policy_exit_code(results):
    """0 fully compliant, 1 warnings/unknowns, 2 critical failure.

    An `unknown` can never produce 0 — a policy run that couldn't check
    everything is not a clean run, and a scheduled job should be able to
    tell the difference without parsing the report (§9, §16).
    """
    if any(r["outcome"] == "fail" and r["severity"] == "critical" for r in results):
        return 2
    if any(r["outcome"] in ("fail", "unknown") for r in results):
        return 1
    return 0


def render_policy(results, policy_name="kmo-default"):
    counts = summarise(results)
    lines = [
        f"Policy check — {policy_name}",
        f"{counts['pass']} pass, {counts['fail']} fail, {counts['unknown']} unknown",
        "",
    ]

    for outcome, label in (("fail", "FAIL"), ("pass", "PASS")):
        rows = [r for r in results if r["outcome"] == outcome]
        for r in rows:
            lines.append(f"[{label}] {r['rule']} - {r['description']}")
            if outcome == "fail":
                lines.append(f"        {r['detail']}  (severity: {r['severity']})")

    unknowns = [r for r in results if r["outcome"] == "unknown"]
    lines.append("")
    if unknowns:
        lines.append("Could not be checked (NOT counted as compliant):")
        for r in unknowns:
            lines.append(f"  [?] {r['rule']} - {r['detail']}")
    else:
        lines.append("Every policy rule was checkable against this snapshot.")

    return "\n".join(lines)
