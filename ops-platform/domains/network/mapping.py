"""netdiag output → Finding contracts.

Like the diagnostics mapping, this does **no interpretation**. netdiag
already decides severity, confidence, the blame partition and the next
step, and it has 55 field-tested rules behind those decisions. Nothing
here second-guesses them.

Two things worth recording, because both were discovered rather than
assumed:

**netdiag and Diagnostic Companion converged independently.** Same
severity words (`critical`/`warning`), same confidence words
(`certain`/`likely`), and a collector envelope with the same shape
(`status` / `duration_ms` / `privilege_level` / `data`). Two tools built
separately in different languages arrived at the same model, which is
why this mapping is field-for-field rather than a translation layer.

**netdiag's hygiene rules are security findings, not network ones.**
`hygiene_poisoning_surface` (the Responder attack), `hygiene_smb1_enabled`
(WannaCry's vector), `hygiene_rdp_without_nla` and
`hygiene_risky_listeners` describe exposure, not connectivity. Tagging
them `security` is what makes cross-signal correlation possible later —
without the tag, a security exposure and a health symptom look like the
same kind of thing.
"""

import sys
from typing import List, Optional

from contracts import Coverage, Finding, sort_findings

SOURCE = "netdiag"

# Rules that describe security exposure rather than network health.
# Derived from netdiag's own KB (`kb/rules.json`), where every one of
# these sits in its `hygiene` collector.
SECURITY_RULE_PREFIXES = ("hygiene_",)

# Individual rules outside the hygiene collector that are still about
# exposure. Kept as an explicit list rather than pattern-matching on
# rule text, which would silently reclassify rules when their wording
# changes.
SECURITY_RULE_IDS = frozenset({
    "dns_hijack",          # resolver answering with addresses it should not
    "tls_inspection_ca",   # a middlebox is decrypting TLS
    "doh_bypass_active",   # DNS-over-HTTPS routing around local policy
    "browser_doh_enabled",
})


def is_security_rule(rule_id: str) -> bool:
    return rule_id in SECURITY_RULE_IDS or rule_id.startswith(
        SECURITY_RULE_PREFIXES
    )


def extract_coverage(payload: dict) -> Coverage:
    """Count collectors that actually ran.

    netdiag reports every collector with a status and marks skips
    explicitly — "absence is never health" is its stated discipline too.
    A missing collectors block yields zero knowledge, never assumed
    completeness.
    """
    collectors = (payload.get("snapshot") or {}).get("collectors") or {}
    if not collectors:
        return Coverage(checked=0, total=0)

    ran = sum(
        1 for c in collectors.values()
        if isinstance(c, dict) and c.get("status") == "ok"
    )
    return Coverage(checked=ran, total=len(collectors))


def extract_not_checked(payload: dict) -> List[tuple]:
    """Collectors that did not run, with netdiag's stated reason."""
    collectors = (payload.get("snapshot") or {}).get("collectors") or {}
    return [
        (name, c.get("status"), c.get("reason") or c.get("skip_reason"))
        for name, c in collectors.items()
        if isinstance(c, dict) and c.get("status") != "ok"
    ]


def _tags_for(raw: dict) -> tuple:
    tags = []
    if is_security_rule(raw.get("id", "")):
        tags.append("security")
    layer = raw.get("layer")
    if layer:
        # OSI layer is netdiag-specific but useful for correlation:
        # an L1 fault and an L7 symptom on one machine is a different
        # story from two L7 symptoms.
        tags.append(f"layer:{layer}")
    return tuple(tags)


def to_findings(payload: dict, machine_id: Optional[str] = None) -> List[Finding]:
    """Map a netdiag JSON payload into Finding records."""
    snapshot = payload.get("snapshot") or {}
    machine = machine_id or snapshot.get("hostname") or "unknown"
    timestamp = snapshot.get("collected_at")
    coverage = extract_coverage(payload)

    findings = []
    for raw in payload.get("findings") or []:
        try:
            findings.append(
                Finding(
                    id=raw["id"],
                    source_module=SOURCE,
                    machine_id=machine,
                    severity=raw["severity"],
                    confidence=raw["confidence"],
                    message=raw["finding"],
                    plain_message=raw.get("for_user"),
                    suggested_action=raw.get("next_step"),
                    coverage=coverage,
                    tags=_tags_for(raw),
                    timestamp=timestamp,
                )
            )
        except (KeyError, ValueError) as exc:
            print(
                f"  warning: skipped unmappable netdiag finding "
                f"{raw.get('id', '?')}: {exc}",
                file=sys.stderr,
            )

    return sort_findings(findings)
