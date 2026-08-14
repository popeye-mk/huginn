"""
Interpreter: loads pattern_kb/entries.yaml, matches it against a
snapshot, and produces plain-language findings (spec §6).

Design note: the spec's own examples use ad-hoc match keys
(disk_free_percent_below, smart_reallocated_sectors_above, ...) — one
per rule. v0 generalises that to a single {path, op, value} shape so
new rules never need a new code path, only a new YAML entry. This is
the "no ML needed, just an if-this-then-that rule set that's easy to
keep extending" principle from §6, taken one step further.
"""

import os

import yaml

from resources import resource_path

KB_PATH = resource_path("pattern_kb", "entries.yaml")
CHAINS_PATH = resource_path("pattern_kb", "chains.yaml")

class _Missing:
    """Sentinel: the path does not exist in this snapshot at all.

    Distinct from None, which means the collector looked and found
    nothing there. The difference matters: a rule written as
    `{op: equals, value: null}` should fire when a collector reports
    `gateway: null` (there genuinely is no gateway) but NOT when a
    collector never reported a `gateway` field at all — that is missing
    data, and missing data must never produce a finding (§3.4).

    Collapsing the two is how a rule ends up firing on every healthy
    machine whose collector predates the field.
    """

    def __repr__(self):
        return "<missing>"


MISSING = _Missing()

OPS = {
    "below": lambda actual, value: actual is not None and actual < value,
    "above": lambda actual, value: actual is not None and actual > value,
    "equals": lambda actual, value: actual == value,
}


def load_rules(path=KB_PATH):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def load_chains(path=CHAINS_PATH):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _get_by_path(snapshot, path):
    """Resolve a dot path, returning MISSING (not None) if it isn't there."""
    node = snapshot
    for part in path.split("."):
        if part == "sections":
            node = node.get("sections", {})
            continue
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return MISSING
    return node


def _section_status(snapshot, path):
    """The collector id is always the first segment of a rule's path."""
    collector_id = path.split(".")[0]
    section = snapshot.get("sections", {}).get(collector_id)
    return section["status"] if section else None


def evaluate(snapshot, rules=None):
    """Returns (findings, worth_checking, not_checked).

    findings: certain/likely matches, headline material.
    worth_checking: possible-confidence matches, never headline (§3.5).
    not_checked: collector ids whose section status != "ok" (§3.4).
    """
    rules = rules if rules is not None else load_rules()

    not_checked = [
        (cid, sec["status"], sec["reason"])
        for cid, sec in snapshot.get("sections", {}).items()
        if sec["status"] != "ok"
    ]

    matched = []
    for rule in rules:
        match = rule["match"]
        status = _section_status(snapshot, match["path"])
        if status != "ok":
            continue  # absence is never health — no data, no finding (§3.4)

        actual = _get_by_path(snapshot, "sections." + match["path"])
        if actual is MISSING:
            # The collector ran but never reported this field. No data,
            # no finding — the same rule as a skipped collector (§3.4).
            continue

        op_fn = OPS[match["op"]]
        if op_fn(actual, match["value"]):
            # Capture the collector id HERE, while `match` is still this
            # rule's match block. Reading rule["match"] again in the
            # rendering loop below would silently pick up whichever rule
            # the matching loop happened to end on.
            matched.append((rule, actual, match["path"].split(".")[0]))

    # Rule precedence (§6): explicit `supersedes` wins.
    superseded_ids = set()
    for rule, _, _ in matched:
        superseded_ids.update(rule.get("supersedes", []))
    matched = [(r, v, c) for r, v, c in matched if r["id"] not in superseded_ids]

    findings, worth_checking = [], []
    for rule, actual, collector_id in matched:
        finding = {
            "id": rule["id"],
            # Which collector produced the evidence for this finding.
            # Derived from the rule's own match path rather than parsed
            # out of the rule id — ids are human-readable labels, not a
            # data structure, and "high_error_log_volume" does not start
            # with "logs". Consumers (HTML evidence blocks, fix
            # planning) need the real answer, not a naming convention.
            "collector": collector_id,
            "finding": rule["finding"].format(value=actual),
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "next_step": rule.get("next_step"),
        }
        if rule["confidence"] == "possible":
            worth_checking.append(finding)
        else:
            findings.append(finding)

    severity_order = {"critical": 0, "warning": 1}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    return findings, worth_checking, not_checked


def exit_code(findings):
    """0 healthy, 1 warnings, 2 critical. Only `certain`-confidence
    findings may drive a 2 (§3.5, §16)."""
    if any(f["severity"] == "critical" and f["confidence"] == "certain" for f in findings):
        return 2
    if findings:
        return 1
    return 0


def resolve_chains(findings, chains=None):
    """Root-cause chains (§14.1) — a *display* layer, not a data layer.

    Returns (fired_chains, remaining_findings). exit_code() should
    always be computed from the original flat `findings`, never from
    this function's output — a narrative wrapper must never soften the
    signal automation reacts to (§16). This only changes how a human
    reads the report.

    A chain fires only if every id in its `when` list is present among
    findings — which already excludes `possible`-confidence items,
    since those never reach `findings` (they go to worth_checking).
    Incomplete evidence means no chain, not an invented one.
    """
    chains = chains if chains is not None else load_chains()
    present_ids = {f["id"] for f in findings}
    collector_by_id = {f["id"]: f.get("collector") for f in findings}

    fired, consumed = [], set()
    for chain in chains:
        when_ids = set(chain["when"])
        if when_ids <= present_ids and not (when_ids & consumed):
            fired.append({
                "type": "chain",
                "id": chain["id"],
                "story": " ".join(chain["story"].split()),  # collapse YAML folded whitespace
                "root": chain["root"],
                "confidence": chain["confidence"],
                "members": sorted(when_ids),
                # Evidence sections behind this story, so a reader can
                # expand the raw data the narrative was built from.
                "collectors": sorted(
                    {collector_by_id[i] for i in when_ids if collector_by_id.get(i)}
                ),
            })
            consumed |= when_ids

    remaining = [f for f in findings if f["id"] not in consumed]
    return fired, remaining
