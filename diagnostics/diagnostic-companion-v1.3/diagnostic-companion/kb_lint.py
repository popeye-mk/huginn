"""`diag kb lint` — pre-commit discipline for the knowledge base (spec §12.3).

The KB is the part of this tool most likely to rot. Rules get added
from real tickets at 5pm on a Friday, thresholds get invented, and a
year later the tool is confidently wrong. Code has a compiler and a
test suite to stop that; YAML has nothing unless you build it.

What this checks, and why each one exists:

* **Structural completeness** — a rule missing `next_step` produces a
  finding a technician can't act on.
* **Referential integrity** — `supersedes`, chain `when` lists, triage
  `weight` lists and triage `collectors` all name things by string.
  Nothing catches a typo in a string except a check like this. The spec
  calls this out directly: v4 shipped triage weights pointing at
  `thermal_throttle` and `captive_portal`, neither of which existed.
* **Threshold provenance** — "disk_free < 10%" is a judgement call, not
  a law of nature. Every threshold needs a comment saying where the
  number came from, so the next person can argue with it.
* **Fixture coverage** — a rule with no fixture that makes it fire is a
  rule nobody has ever seen work.
* **Quarantine** — a `source: ticket` rule with no reviewer is
  overfitted to one machine on one bad Tuesday until a human says
  otherwise. It may fire, but only into "worth checking" (§12.1).

Exit codes: 0 clean, 1 warnings only, 2 errors present.
"""

import json
import os
import re

import yaml

from resources import resource_path

BASE = os.path.dirname(os.path.abspath(__file__))
KB_PATH = resource_path("pattern_kb", "entries.yaml")
CHAINS_PATH = resource_path("pattern_kb", "chains.yaml")
TRIAGE_PATH = resource_path("pattern_kb", "triage.yaml")
FIXTURE_DIR = resource_path("tests", "fixtures")

REQUIRED_RULE_FIELDS = ("id", "match", "finding", "severity", "confidence", "next_step")
VALID_SEVERITY = {"critical", "warning"}
VALID_CONFIDENCE = {"certain", "likely", "possible"}
VALID_OPS = {"below", "above", "equals"}
VALID_SOURCES = {"seed", "ticket", "vendor_kb", "manual"}


class Issue:
    def __init__(self, level, where, message):
        self.level = level  # "error" | "warning"
        self.where = where
        self.message = message

    def __repr__(self):
        return f"[{self.level.upper()}] {self.where}: {self.message}"


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def _raw_lines(path):
    with open(path, encoding="utf-8") as f:
        return f.read().splitlines()


def check_rules(rules, raw_lines):
    issues = []
    seen_ids = set()

    for rule in rules:
        rid = rule.get("id", "<no id>")

        for field in REQUIRED_RULE_FIELDS:
            if field not in rule:
                issues.append(Issue("error", rid, f"missing required field '{field}'"))

        if rid in seen_ids:
            issues.append(Issue("error", rid, "duplicate rule id"))
        seen_ids.add(rid)

        if rule.get("severity") not in VALID_SEVERITY:
            issues.append(Issue("error", rid, f"invalid severity {rule.get('severity')!r}"))
        if rule.get("confidence") not in VALID_CONFIDENCE:
            issues.append(Issue("error", rid, f"invalid confidence {rule.get('confidence')!r}"))

        match = rule.get("match") or {}
        if match.get("op") not in VALID_OPS:
            issues.append(Issue("error", rid, f"invalid match op {match.get('op')!r}"))
        if not match.get("path"):
            issues.append(Issue("error", rid, "match has no path"))

        # A {value} placeholder in the finding text with a boolean match
        # renders as "... (True% free)" — nonsense a reader would notice
        # but a test might not.
        if match.get("op") == "equals" and "{value}" in (rule.get("finding") or ""):
            issues.append(Issue(
                "warning", rid,
                "finding interpolates {value} on an equals match — usually reads as True/False"
            ))

    # Referential integrity of supersedes
    for rule in rules:
        for target in rule.get("supersedes", []):
            if target not in seen_ids:
                issues.append(Issue(
                    "error", rule.get("id"), f"supersedes unknown rule {target!r}"
                ))

    # Circular supersedes: A supersedes B and B supersedes A
    supersedes = {r["id"]: set(r.get("supersedes", [])) for r in rules if "id" in r}
    for rid, targets in supersedes.items():
        for target in targets:
            if rid in supersedes.get(target, set()):
                issues.append(Issue("error", rid, f"circular supersedes with {target!r}"))

    issues.extend(_check_threshold_provenance(rules, raw_lines))
    issues.extend(_check_rule_provenance(rules))
    return issues


def _check_threshold_provenance(rules, raw_lines):
    """Every numeric threshold needs a comment saying where it came from (§12.3).

    Implemented as a text scan rather than a schema field on purpose:
    the comment should sit next to the number in the YAML where someone
    editing the threshold will actually read it, not in a field they
    can fill with "TODO".
    """
    issues = []
    for rule in rules:
        match = rule.get("match") or {}
        value = match.get("value")
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            continue

        rid = rule.get("id")
        # Find the rule's block in the raw text and look for a comment
        # within it or on the two lines above the id.
        block = _rule_block(raw_lines, rid)
        if not any("#" in line for line in block):
            issues.append(Issue(
                "warning", rid,
                f"threshold {value} has no comment explaining where the number came from"
            ))
    return issues


def _rule_block(raw_lines, rule_id):
    """Lines belonging to one rule, plus the comment lines directly above it."""
    start = None
    for i, line in enumerate(raw_lines):
        if re.match(rf"^-\s+id:\s*{re.escape(str(rule_id))}\s*$", line.strip()):
            start = i
            break
    if start is None:
        return []

    # walk backwards over an immediately-preceding comment block
    top = start
    while top > 0 and raw_lines[top - 1].strip().startswith("#"):
        top -= 1

    end = start + 1
    while end < len(raw_lines) and not raw_lines[end].strip().startswith("- id:"):
        end += 1
    return raw_lines[top:end]


def _check_rule_provenance(rules):
    """Ticket-learned rules need review before they can headline (§12.1)."""
    issues = []
    for rule in rules:
        rid = rule.get("id")
        prov = rule.get("provenance")
        if prov is None:
            issues.append(Issue("warning", rid, "no provenance block — source unknown"))
            continue

        source = prov.get("source")
        if source not in VALID_SOURCES:
            issues.append(Issue("error", rid, f"invalid provenance.source {source!r}"))

        if source == "ticket" and not prov.get("reviewed_by"):
            if rule.get("confidence") != "possible":
                issues.append(Issue(
                    "error", rid,
                    "ticket-learned rule is unreviewed but has confidence "
                    f"{rule.get('confidence')!r} — quarantined rules must be 'possible' "
                    "so they render as 'worth checking', never as a headline (§12.1)"
                ))
    return issues


def check_chains(chains, rule_ids):
    issues = []
    seen = set()
    for chain in chains:
        cid = chain.get("id", "<no id>")
        if cid in seen:
            issues.append(Issue("error", cid, "duplicate chain id"))
        seen.add(cid)

        for field in ("when", "root", "confidence", "story"):
            if field not in chain:
                issues.append(Issue("error", cid, f"missing required field '{field}'"))

        for member in chain.get("when", []):
            if member not in rule_ids:
                issues.append(Issue("error", cid, f"'when' names unknown rule {member!r}"))

        root = chain.get("root")
        if root and root not in chain.get("when", []):
            issues.append(Issue("error", cid, f"root {root!r} is not among its own 'when' members"))

        if len(chain.get("when", [])) < 2:
            issues.append(Issue("warning", cid, "chain with fewer than 2 members explains nothing"))
    return issues


def check_triage(profiles, rule_ids, known_collectors):
    """The check that would have caught v4's dangling weights (§12.3)."""
    issues = []
    for profile in profiles:
        sid = profile.get("symptom", "<no symptom>")

        for collector in profile.get("collectors", []):
            if collector not in known_collectors:
                issues.append(Issue("error", sid, f"references unknown collector {collector!r}"))

        for rule_id in profile.get("weight", []):
            if rule_id not in rule_ids:
                issues.append(Issue("error", sid, f"weights unknown rule {rule_id!r}"))

        if not profile.get("collectors"):
            issues.append(Issue("error", sid, "profile runs no collectors"))
    return issues


def check_fixture_coverage(rules):
    """Every rule needs at least one fixture that makes it fire (§12.3).

    Skipped rather than failed when the fixture directory is absent.
    This check is about the health of the repository, and a packaged
    binary is not a repository — reporting "no fixture covers this rule"
    to an end user running `diag kb lint` would be both alarming and
    meaningless.
    """
    from interpreter import evaluate

    if not os.path.isdir(FIXTURE_DIR):
        return []

    fired = set()
    for name in sorted(os.listdir(FIXTURE_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(FIXTURE_DIR, name), encoding="utf-8") as f:
            try:
                snapshot = json.load(f)
            except json.JSONDecodeError:
                continue
        if "sections" not in snapshot:
            continue
        findings, worth, _ = evaluate(snapshot, rules)
        fired |= {f["id"] for f in findings + worth}

    return [
        Issue("warning", rule["id"], "no fixture in tests/fixtures makes this rule fire")
        for rule in rules
        if rule.get("id") not in fired
    ]


def lint(known_collectors=None):
    known_collectors = known_collectors or {
        "system", "network", "disk", "logs", "battery", "wifi", "smart",
    }

    rules = _load(KB_PATH)
    chains = _load(CHAINS_PATH)
    profiles = _load(TRIAGE_PATH)
    rule_ids = {r["id"] for r in rules if "id" in r}

    issues = []
    issues += check_rules(rules, _raw_lines(KB_PATH))
    issues += check_chains(chains, rule_ids)
    issues += check_triage(profiles, rule_ids, known_collectors)
    issues += check_fixture_coverage(rules)
    return issues


def render_lint(issues, rule_count=None):
    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    lines = ["diag kb lint"]
    if rule_count is not None:
        lines.append(f"{rule_count} rules checked")
    lines.append(f"{len(errors)} errors, {len(warnings)} warnings")
    lines.append("")

    for issue in errors + warnings:
        lines.append(f"[{issue.level.upper():7}] {issue.where}: {issue.message}")

    if not issues:
        lines.append("Knowledge base is clean.")
    return "\n".join(lines)


def lint_exit_code(issues):
    if any(i.level == "error" for i in issues):
        return 2
    if issues:
        return 1
    return 0
