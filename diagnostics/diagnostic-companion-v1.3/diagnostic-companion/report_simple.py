"""diag simple — end-user mode (spec §14.2): "read me the colours".

Accessible by construction: every line carries a text label (OK/WARN/
FAIL/?), never colour alone. No emoji in terminal output (§14.2) — see
report.py's docstring for why that rule exists and was already broken
once in this codebase.
"""

import hashlib

TOPICS = [
    {"label": "Internet connection", "collector": "network",
     "critical": ["gateway_unreachable", "dns_resolution_failing"]},
    {"label": "Disk space", "collector": "disk",
     "critical": ["disk_free_critical"], "warning": ["disk_free_warning"]},
    {"label": "Recent system errors", "collector": "logs",
     "warning": ["high_error_log_volume"]},
    {"label": "Disk health (SMART)", "collector": "smart",
     "critical": ["smart_reallocated"]},
    {"label": "Battery health", "collector": "battery",
     "warning": ["battery_health_low"]},
    {"label": "Wi-Fi signal", "collector": "wifi",
     "warning": ["wifi_weak"]},
]


def generate_support_code(snapshot, findings):
    """Deterministic short code a user can read over the phone (§14.2).

    v1 simplification, stated plainly: this is a hash truncated to 4
    hex characters, not yet checksummed against misreads, and there is
    no `diag decode` lookup implemented to turn it back into findings.
    Both are real gaps against the spec (§12.4's kb_version tracking is
    also not wired in — this uses schema_version as a stand-in).
    """
    material = ",".join(sorted(f["id"] for f in findings)) + "|" + snapshot["schema_version"]
    digest = hashlib.sha256(material.encode()).hexdigest().upper()
    return f"DC-{digest[:4]}"


def render_simple(snapshot, findings, not_checked):
    finding_by_id = {f["id"]: f for f in findings}
    not_checked_by_collector = {cid: (status, reason) for cid, status, reason in not_checked}

    lines = []
    for topic in TOPICS:
        collector = topic["collector"]
        label = f"{topic['label']:<22}"

        if collector in not_checked_by_collector:
            _status, reason = not_checked_by_collector[collector]
            lines.append(f"[?]    {label} Could not check ({reason})")
            continue

        critical_hit = next(
            (finding_by_id[fid] for fid in topic.get("critical", []) if fid in finding_by_id), None
        )
        warning_hit = next(
            (finding_by_id[fid] for fid in topic.get("warning", []) if fid in finding_by_id), None
        )

        if critical_hit:
            lines.append(f"[FAIL] {label} {critical_hit['finding']}")
        elif warning_hit:
            lines.append(f"[WARN] {label} {warning_hit['finding']}")
        else:
            lines.append(f"[OK]   {label} OK")

    lines.append("")
    lines.append(f"Support code: {generate_support_code(snapshot, findings)}")
    return "\n".join(lines)
