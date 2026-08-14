"""Terminal report renderer (spec §14.2, §15.11).

Accessibility rules, applied strictly because a terminal is the worst
case for both:

* **No colour-only signalling.** Every line carries a text label, so
  the report is identical in meaning to a colour-blind reader, a
  monochrome terminal, and a log file someone piped this into.
* **No emoji.** §14.2 is explicit: Windows consoles and legacy SSH
  terminals mangle them. An earlier version used "⚪" here, which is
  exactly the mistake the rule exists to prevent. Emoji are permitted
  in the HTML report only.

The verdict block at the top comes from verdict.py, shared with the
HTML report so the two can never disagree about what matters most.
"""

SEVERITY_LABEL = {"critical": "FAIL", "warning": "WARN"}

RULE = "=" * 66


def _wrap(text, width=66, indent=""):
    """Wrap without pulling in textwrap's tab/whitespace normalisation."""
    words, lines, current = str(text).split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) + len(indent) > width and current:
            lines.append(indent + current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(indent + current)
    return lines


def render_text(snapshot, findings, worth_checking, not_checked, chains=None,
                diff=None, decoded_codes=None, verdict=None, score=None):
    chains = chains or []
    decoded_codes = decoded_codes or []
    lines = []

    lines.append(f"Diagnostic Companion — {snapshot.get('hostname', 'unknown')} "
                 f"({snapshot.get('os', '?')})")
    lines.append(f"collected_at: {snapshot.get('collected_at', '?')}  "
                 f"schema: {snapshot.get('schema_version', '?')}")

    # --- verdict ---
    if verdict:
        banner = {"ok": "ALL CLEAR", "warning": "NEEDS ATTENTION",
                  "critical": "ACTION REQUIRED"}.get(verdict["level"], "RESULT")
        lines.append("")
        lines.append(RULE)
        lines.append(f"  {banner}")
        lines.append(RULE)
        lines.extend(_wrap(verdict["headline"], indent="  "))
        lines.append("")
        lines.extend(_wrap(verdict["detail"], indent="  "))
        if verdict.get("action"):
            lines.append("")
            lines.extend(_wrap(f"Do this first: {verdict['action']}", indent="  "))
        if verdict.get("coverage_caveat"):
            lines.append("")
            lines.extend(_wrap(verdict["coverage_caveat"], indent="  "))
        lines.append(RULE)

    if score is not None:
        total = len(snapshot.get("sections") or {})
        checked = total - len(not_checked)
        lines.append("")
        lines.append(f"Health score: {score['score']}/100   "
                     f"({checked}/{total} checks ran)")

    # --- diff ---
    if diff is not None:
        lines.append("")
        lines.append("Changed since baseline:")
        if diff["value_changes"] or diff["new_finding_ids"] or diff["resolved_finding_ids"]:
            for line in diff["value_changes"]:
                lines.append(f"  * {line}")
            for fid in diff["new_finding_ids"]:
                lines.append(f"  * NEW finding: {fid}")
            for fid in diff["resolved_finding_ids"]:
                lines.append(f"  * RESOLVED since baseline: {fid}")
        else:
            lines.append("  No differences from baseline.")

    # --- findings ---
    lines.append("")
    lines.append("Details:")

    # Chains lead: one story instead of several symptoms (§14.1).
    # Members are not repeated below — resolve_chains() removed them.
    for chain in chains:
        lines.append("")
        lines.append("  [ROOT CAUSE]")
        lines.extend(_wrap(chain["story"], indent="    "))
        lines.append(f"    (explains: {', '.join(chain['members'])} — "
                     f"confidence: {chain['confidence']})")

    if not findings and not chains:
        lines.append("  [OK]   Nothing wrong was found in the checks that ran.")

    for f in findings:
        label = SEVERITY_LABEL.get(f["severity"], "WARN")
        lines.append("")
        lines.extend(_wrap(f"[{label}] {f['finding']}", indent="  "))
        if f.get("next_step"):
            lines.extend(_wrap(f"-> {f['next_step']}", indent="      "))

    if worth_checking:
        lines.append("")
        lines.append("Worth checking (possible, not confirmed):")
        for f in worth_checking:
            lines.extend(_wrap(f"[?] {f['finding']}", indent="  "))
            if f.get("next_step"):
                lines.extend(_wrap(f"-> {f['next_step']}", indent="      "))

    # Decoded codes are context for a technician, not findings — nothing
    # here drives an exit code (§10).
    if decoded_codes:
        lines.append("")
        lines.append("Error codes found in the logs:")
        for code in decoded_codes:
            lines.append("")
            lines.append(f"  {code['code']} — {code.get('name') or code.get('meaning')}")
            lines.extend(_wrap(code["cause"], indent="      "))
            lines.extend(_wrap(f"-> {code['next_step']}", indent="      "))

    # --- coverage ---
    lines.append("")
    if not_checked:
        lines.append("Not checked:")
        for cid, status, reason in not_checked:
            lines.append(f"  [?] {cid} - {status}: {reason}")
        lines.append("")
        lines.extend(_wrap(
            "The absence of a finding above is not evidence that these are fine.",
            indent="  "))
    else:
        lines.append("Not checked: nothing — every check ran and produced data.")

    return "\n".join(lines)
