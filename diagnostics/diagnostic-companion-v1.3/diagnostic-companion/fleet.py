"""Fleet correlation and health scoring (spec §8, §14.6).

Six machines reporting the same DNS failure at 09:02 means the DNS
server is broken — not six machines. Correlation turns an alert storm
into one environment-level conclusion and one ticket.

Two properties this module is built around, both from the spec:

**Correlation needs a denominator (§8).** "6 assets report this" is
meaningless without "of 9 checked". More subtly: an asset whose
relevant collector was *skipped* must be excluded from both numbers,
not counted as healthy. A machine that couldn't check its disk is not
evidence that its disk is fine. Getting this wrong would make the
denominator actively misleading, which is worse than omitting it.

**The health score is explainable by construction (§14.6).** It is
100 minus a list of deductions, and every deduction is returned
alongside the number. There is no weighting model to defend, because
there is no model — when a manager asks "why is this machine a 61?",
the answer is the list. A score computed over partial data always
carries its coverage (`61 · 7/11 checked`) so it can never be mistaken
for a confident number over complete data.
"""

import json
import os
from collections import defaultdict

from interpreter import evaluate

# Deduction per finding. Blunt on purpose: two tiers, no tuning knobs.
# A scoring system with many hand-tuned weights is one nobody can
# defend in a meeting, which defeats the point of having a score.
DEDUCTION = {"critical": 25, "warning": 8}


def load_snapshots(paths):
    """Load snapshot JSON files, skipping anything that isn't one."""
    snapshots = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                snapshot = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(snapshot, dict) and "sections" in snapshot:
            snapshot.setdefault("_source", os.path.basename(path))
            snapshots.append(snapshot)
    return snapshots


def health_score(snapshot):
    """Returns {score, deductions, checked, total, coverage}.

    `deductions` is the explanation, not a debug aid — callers are
    expected to show it.
    """
    findings, _worth, not_checked = evaluate(snapshot)

    deductions = []
    for finding in findings:
        amount = DEDUCTION.get(finding["severity"], 0)
        deductions.append({
            "id": finding["id"],
            "amount": amount,
            "reason": finding["finding"],
        })

    score = max(0, 100 - sum(d["amount"] for d in deductions))

    total = len(snapshot.get("sections", {}))
    checked = total - len(not_checked)

    return {
        "hostname": snapshot.get("hostname", "unknown"),
        "score": score,
        "deductions": deductions,
        "checked": checked,
        "total": total,
        "coverage": f"{checked}/{total} checked",
        "top_finding": findings[0]["finding"] if findings else None,
    }


def correlate(snapshots):
    """Group identical finding ids across assets, with an honest denominator.

    Returns a list of {finding_id, affected, checked, hostnames,
    excluded, environment_level} sorted by how many assets are affected.

    `checked` counts only assets whose relevant collector actually ran.
    `excluded` names the assets left out of both numbers, so the gap
    between affected/checked and the fleet size is never silent.
    """
    per_asset = {}
    for snapshot in snapshots:
        host = snapshot.get("hostname", snapshot.get("_source", "unknown"))
        findings, _worth, _not_checked = evaluate(snapshot)
        per_asset[host] = {
            "findings": {f["id"]: f for f in findings},
            "sections": snapshot.get("sections", {}),
        }

    # Which collector backs each finding id we saw anywhere in the fleet.
    collector_for = {}
    for asset in per_asset.values():
        for fid, finding in asset["findings"].items():
            collector_for.setdefault(fid, finding.get("collector"))

    results = []
    for fid, collector_id in collector_for.items():
        affected, eligible, excluded = [], [], []

        for host, asset in per_asset.items():
            section = asset["sections"].get(collector_id)
            # No section, or a section that didn't run, means this asset
            # cannot vote either way (§8, §3.4).
            if section is None or section.get("status") != "ok":
                excluded.append(host)
                continue
            eligible.append(host)
            if fid in asset["findings"]:
                affected.append(host)

        if not affected:
            continue

        results.append({
            "finding_id": fid,
            "collector": collector_id,
            "affected": len(affected),
            "checked": len(eligible),
            "hostnames": sorted(affected),
            "excluded": sorted(excluded),
            # An environment-level conclusion needs a majority AND more
            # than one machine — two of two is not a pattern, it's a
            # coincidence with a small sample.
            "environment_level": len(affected) >= 3 and len(affected) * 2 > len(eligible),
            "example": next(
                asset["findings"][fid]["finding"]
                for asset in per_asset.values()
                if fid in asset["findings"]
            ),
        })

    results.sort(key=lambda r: (-r["affected"], r["finding_id"]))
    return results


def render_fleet(snapshots):
    """The ranked board (§14.6) plus correlated conclusions (§8)."""
    scores = sorted(
        (health_score(s) for s in snapshots),
        key=lambda s: (s["score"], s["hostname"]),
    )
    correlations = correlate(snapshots)

    lines = [f"Fleet health — {len(snapshots)} asset(s)", ""]

    environment = [c for c in correlations if c["environment_level"]]
    if environment:
        lines.append("Environment-level conclusions (open ONE ticket, not several):")
        for c in environment:
            lines.append(
                f"  [SHARED] {c['affected']} of {c['checked']} checked assets report "
                f"{c['finding_id']}"
            )
            lines.append(f"           {c['example']}")
            lines.append(f"           Affected: {', '.join(c['hostnames'])}")
            if c["excluded"]:
                lines.append(
                    f"           Excluded (collector did not run, not counted as healthy): "
                    f"{', '.join(c['excluded'])}"
                )
        lines.append("")

    lines.append("Ranked by health score (lowest first):")
    for s in scores:
        top = s["top_finding"] or "no findings"
        lines.append(f"  {s['score']:3d} · {s['coverage']:<16} {s['hostname']:<10} {top}")

    lines.append("")
    lines.append("Score = 100 minus listed deductions. Worst asset's breakdown:")
    if scores:
        worst = scores[0]
        if worst["deductions"]:
            for d in worst["deductions"]:
                lines.append(f"  -{d['amount']:<3} {d['id']}: {d['reason']}")
        else:
            lines.append("  (no deductions — nothing was found on the lowest-scoring asset)")

    if any(s["checked"] < s["total"] for s in scores):
        lines.append("")
        lines.append(
            "Coverage figures are not decoration: a score computed over partial "
            "data is not the same claim as one over complete data."
        )

    return "\n".join(lines)
