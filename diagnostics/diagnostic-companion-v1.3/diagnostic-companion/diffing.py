"""Baseline storage + snapshot comparison (spec §6.1, §18).

"The single most useful question in troubleshooting is 'what changed?'"
— this compares two snapshots and surfaces value-level deltas (disk
free space, DNS servers, gateway, error-log volume) plus which findings
are new or resolved since the baseline was taken.
"""

DISK_FREE_DELTA_THRESHOLD_PP = 1.0  # percentage points — ignore noise


def _get(snapshot, section, key, default=None):
    return snapshot.get("sections", {}).get(section, {}).get("data", {}).get(key, default)


def diff_values(old_snapshot, new_snapshot):
    """Human-readable lines describing what changed at the data level."""
    changes = []

    old_free = _get(old_snapshot, "disk", "min_free_percent")
    new_free = _get(new_snapshot, "disk", "min_free_percent")
    if old_free is not None and new_free is not None:
        delta = new_free - old_free
        if abs(delta) >= DISK_FREE_DELTA_THRESHOLD_PP:
            changes.append(f"Disk free space: {old_free}% -> {new_free}% ({delta:+.1f}pp)")

    old_dns = _get(old_snapshot, "network", "dns_servers")
    new_dns = _get(new_snapshot, "network", "dns_servers")
    if old_dns is not None and new_dns is not None and old_dns != new_dns:
        changes.append(f"DNS servers: {old_dns} -> {new_dns}")

    old_gw = _get(old_snapshot, "network", "gateway")
    new_gw = _get(new_snapshot, "network", "gateway")
    if old_gw != new_gw:
        changes.append(f"Default gateway: {old_gw} -> {new_gw}")

    old_errs = _get(old_snapshot, "logs", "error_count")
    new_errs = _get(new_snapshot, "logs", "error_count")
    if old_errs is not None and new_errs is not None and old_errs != new_errs:
        delta = new_errs - old_errs
        changes.append(f"Error log count: {old_errs} -> {new_errs} ({delta:+d})")

    return changes


def diff_findings(old_findings, new_findings):
    """Which finding ids are new since the baseline, and which resolved."""
    old_ids = {f["id"] for f in old_findings}
    new_ids = {f["id"] for f in new_findings}
    return {
        "new_finding_ids": sorted(new_ids - old_ids),
        "resolved_finding_ids": sorted(old_ids - new_ids),
    }


def build_diff(old_snapshot, new_snapshot, old_findings, new_findings):
    result = diff_findings(old_findings, new_findings)
    result["value_changes"] = diff_values(old_snapshot, new_snapshot)
    return result
