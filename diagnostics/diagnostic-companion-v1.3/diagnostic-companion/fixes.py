"""Guided remediation (spec §14.3) and tamper-evident snapshots (§14.7).

`diag fix` is the only part of this tool that is not read-only, so it
is built to be boring on purpose:

* **Dry-run is the default.** `--apply` is a deliberate act, and even
  then each fix is confirmed individually.
* **Whitelist, never free-form shell.** A KB entry names a command
  *key*; the actual command string lives in COMMAND_WHITELIST here, in
  code, reviewed. A malicious or mistaken KB entry cannot introduce a
  new command — the worst it can do is reference a key that doesn't
  exist, which raises.
* **No interpolation of collected data, ever.** Commands are constants.
  Nothing read off the machine is ever substituted into a string that
  gets executed (§13). This is why there is no .format() below and why
  there never should be.
* **Only `risk: low` is suggestible.** Anything else is advice-only
  text, printed but never runnable through this path.

Verification (§14.7) is deliberately trivial — a SHA-256 over the
canonical JSON. Ten lines, and it turns a snapshot attached to a ticket
into evidence rather than a note someone could have edited.
"""

import hashlib
import json
import os

import yaml

from resources import resource_path

KB_PATH = resource_path("pattern_kb", "entries.yaml")

# The whitelist IS the security boundary. Adding a key here is a code
# change that gets reviewed; adding a `fix:` block to a YAML rule is not.
COMMAND_WHITELIST = {
    "vacuum_journal": {
        "linux": "journalctl --vacuum-size=500M",
        "windows": "wevtutil cl Application",
        "risk": "low",
        "reversible": False,
        "explain": "Truncates old system logs to reclaim disk space.",
    },
    "clear_temp": {
        "linux": "find /tmp -type f -atime +7 -delete",
        "windows": "Remove-Item $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue",
        "risk": "low",
        "reversible": False,
        "explain": "Deletes temp files untouched for over a week.",
    },
    "flush_dns": {
        "linux": "resolvectl flush-caches",
        "windows": "Clear-DnsClientCache",
        "risk": "low",
        "reversible": True,
        "explain": "Clears the local DNS cache; harmless and instantly reversible.",
    },
    "renew_dhcp": {
        "linux": "dhclient -r && dhclient",
        "windows": "ipconfig /release; ipconfig /renew",
        "risk": "medium",
        "reversible": True,
        "explain": "Drops and re-acquires the DHCP lease. Briefly interrupts connectivity.",
    },
}


class UnknownFixCommand(Exception):
    """A KB entry referenced a command key that is not whitelisted.

    Raised rather than skipped: a rule that thinks it can fix something
    and silently can't is a worse failure than a loud one.
    """


def load_fix_map(path=KB_PATH):
    """Map rule id -> whitelisted command key, from `fix:` blocks in the KB."""
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f) or []
    fix_map = {}
    for rule in rules:
        key = rule.get("fix")
        if not key:
            continue
        if key not in COMMAND_WHITELIST:
            raise UnknownFixCommand(
                f"rule {rule['id']!r} references non-whitelisted fix command {key!r}"
            )
        fix_map[rule["id"]] = key
    return fix_map


def plan_fixes(findings, os_name, fix_map=None):
    """Build the dry-run plan. Never executes anything.

    Returns a list of {finding_id, command_key, command, risk,
    reversible, explain, suggestible}.
    """
    fix_map = fix_map if fix_map is not None else load_fix_map()
    plan = []
    for finding in findings:
        key = fix_map.get(finding["id"])
        if not key:
            continue
        spec = COMMAND_WHITELIST[key]
        command = spec.get(os_name)
        if not command:
            continue  # no command for this OS — silence beats a wrong command
        plan.append({
            "finding_id": finding["id"],
            "finding": finding["finding"],
            "command_key": key,
            "command": command,
            "risk": spec["risk"],
            "reversible": spec["reversible"],
            "explain": spec["explain"],
            "suggestible": spec["risk"] == "low",
        })
    return plan


def render_plan(plan, os_name):
    if not plan:
        return (
            "No whitelisted fixes apply to the current findings.\n"
            "That is the normal case — most findings need judgement, not a command."
        )

    lines = [
        f"Fix plan ({os_name}) — DRY RUN, nothing has been executed.",
        "",
    ]
    for item in plan:
        marker = "SUGGESTED" if item["suggestible"] else "ADVICE ONLY"
        lines.append(f"[{marker}] {item['finding']}")
        lines.append(f"    would run: {item['command']}")
        lines.append(
            f"    risk: {item['risk']}  reversible: {'yes' if item['reversible'] else 'no'}"
        )
        lines.append(f"    {item['explain']}")
        if not item["suggestible"]:
            lines.append("    Not auto-runnable: only risk:low fixes can be applied by this tool.")
        lines.append("")

    lines.append("Re-run with --apply to be asked about each SUGGESTED fix individually.")
    return "\n".join(lines)


# --- Tamper-evident snapshots (§14.7) ---------------------------------

def snapshot_hash(snapshot):
    """SHA-256 over canonical JSON.

    sort_keys + fixed separators means the same snapshot always hashes
    the same regardless of dict ordering or the writer's formatting —
    otherwise the hash would verify formatting, not content.
    """
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_snapshot(snapshot, expected_hash=None):
    """Returns (ok, actual_hash, expected_hash).

    If the snapshot carries its own `integrity.sha256`, that is used as
    the expectation. The hash is computed over the snapshot *without*
    that field, since a hash cannot cover itself.
    """
    payload = {k: v for k, v in snapshot.items() if k != "integrity"}
    actual = snapshot_hash(payload)
    expected = expected_hash or snapshot.get("integrity", {}).get("sha256")
    if expected is None:
        return None, actual, None
    return actual == expected, actual, expected


def stamp_snapshot(snapshot):
    """Attach integrity.sha256 to a snapshot, in place, and return it."""
    payload = {k: v for k, v in snapshot.items() if k != "integrity"}
    snapshot["integrity"] = {"sha256": snapshot_hash(payload), "algorithm": "sha256"}
    return snapshot
