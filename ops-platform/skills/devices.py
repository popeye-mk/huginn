"""`devices` skill — every machine this platform knows about.

The fleet view. Its job is to make one screen answer "is everything OK
across the machines I look after", which is the question the design doc
is built around.

Three things it refuses to do:

- **Show a score without its coverage.** `42 · 4/7 checked` is a
  different claim from `42`, and only the first is true.
- **Show unchecked machines as healthy.** They are listed separately as
  never checked, because a machine nobody looked at is neither fine nor
  broken.
- **Hide the denominator on shared findings.** "3 affected of 5 checked,
  2 excluded" is what makes a fleet number worth acting on.
"""

from typing import Any

from agents.instance import get_agent


def _render_devices(view) -> list:
    lines = ["  Machines", "  " + "-" * 58]
    for device in view.devices:
        health = view.health.get(device.device_id)
        if health is None:
            lines.append(f"   {device.hostname:28} never checked")
            continue
        flag = "" if health.is_trustworthy else "  (partial)"
        lines.append(
            f"   {device.hostname:28} {health.score:>3}  "
            f"{health.coverage_label}{flag}"
        )
    return lines


def _render_shared(view) -> list:
    if not view.shared_findings:
        return []
    lines = ["", "  Seen on more than one machine", "  " + "-" * 58]
    for finding in view.shared_findings[:8]:
        if finding.get("affected", 0) < 2:
            continue
        tag = "  [environment-level]" if finding.get("environment_level") else ""
        excluded = finding.get("excluded") or []
        note = f"   excluded: {', '.join(excluded)}" if excluded else ""
        lines.append(
            f"   {finding['finding_id']:30} "
            f"{finding['affected']}/{finding['checked']} affected{tag}{note}"
        )
    return lines if len(lines) > 3 else []


def skill_devices(args: str, speaker: Any = None) -> str:
    """One screen: what exists, how it is, and what they share."""
    del speaker, args
    result = get_agent().devices_view()
    if not result.get("ok"):
        return str(result.get("body") or "Fleet view did not complete.")

    view = result["fleet"]
    if not view.devices:
        return (
            "No machines recorded yet. Run `triage` on a machine and it "
            "registers itself — a device list you have to maintain by hand "
            "is one that is always out of date."
        )

    lines = _render_devices(view)
    lines += _render_shared(view)

    lines += ["", "  " + "-" * 58]
    lines.append(f"  {view.total} machine(s), {view.snapshots_read} scan(s) correlated.")
    if view.unassessed:
        lines.append(f"  {len(view.unassessed)} never checked — not the same as healthy.")
    if view.untrustworthy:
        lines.append(
            f"  {len(view.untrustworthy)} score(s) measured over partial data."
        )
    if not view.fleet_available:
        lines.append(f"  Correlation unavailable: {view.unavailable_reason}")
    return "\n".join(lines)


def register(registry) -> None:
    """Registered natively as of 2026-07-27 — see the note in skills/backup.py.

    Reached through the archived fork's router until then, and silently
    absent from the native shell afterwards.
    """
    registry.register(
        "devices",
        skill_devices,
        aliases=[
            "device list", "the fleet", "machines", "inventory",
            "apparaten", "toestellen",                     # NL
            "appareils", "parc",                           # FR
        ],
    )
