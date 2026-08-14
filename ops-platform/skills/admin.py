"""`admin` skill — who gets told, and proof that they actually would.

    admin          show the registered administrator and the live channels
    admin test     send a real test alert through every enabled channel

**`admin test` is the point of this verb.** An alert channel nobody has
ever fired is an assumption, and this project does not run on assumptions:
the whole of chapter two exists because a delivery path was believed to
work for a day after it had ceased to exist. A channel is not configured
until a message has arrived at the other end and a human has seen it.

So the test sends a genuine alert down the genuine path — same builder,
same engines, same config — and reports per channel what happened. It is
marked as a test in its own text so it can never be mistaken for a real
finding, but nothing else about it is simulated.
"""

from datetime import datetime
from typing import Any

from agents.alerting import (
    ADMIN_PATH, configured_channels, deliver, load_admin,
)
from contracts.alert import Alert, summarize
from platform_support import hostname


def _describe(admin: dict) -> str:
    name = (admin.get("name") or "").strip()
    channels = configured_channels(admin)
    quiet = admin.get("quiet_hours") or {}

    lines = ["  REGISTERED ADMINISTRATOR", "  " + "=" * 58]
    if not name and not channels:
        lines += [
            "  Nobody is registered, and no channel is enabled.",
            "",
            "  The guard still runs and still records everything — but if it",
            "  finds something at 03:00, NOBODY WILL BE TOLD.",
            "",
            f"  Fix it:  cp data/admin.example.json {ADMIN_PATH}",
            "           then edit it, then run 'admin test'.",
        ]
        return "\n".join(lines)

    lines.append(f"  name           {name or '(unnamed)'}")
    lines.append(f"  announces at   {admin.get('min_severity', 'warning')} and above")
    if quiet.get("start") is None or quiet.get("end") is None:
        lines.append("  quiet hours    none")
    else:
        lines.append(f"  quiet hours    {quiet['start']:02d}:00–{quiet['end']:02d}:00 "
                     "(warnings held; critical always delivers)")
    lines.append("")
    lines.append("  Channels")
    lines.append("  " + "-" * 58)
    for channel, enabled, where in (
        ("desktop", (admin.get("desktop") or {}).get("enabled"), "this machine only"),
        ("ntfy", (admin.get("ntfy") or {}).get("enabled"),
         (admin.get("ntfy") or {}).get("server", "")),
        ("email", (admin.get("email") or {}).get("enabled"),
         (admin.get("email") or {}).get("to", "")),
    ):
        mark = "on " if enabled else "off"
        lines.append(f"   {mark}  {channel:9} {where}")

    if not channels:
        lines += ["", "  Every channel is off. Findings are recorded and announced",
                  "  to no one."]
    else:
        lines += ["", "  None of this is proof. Run 'admin test' to send a real",
                  "  alert and see which channels actually carry it."]
    return "\n".join(lines)


def _test(admin: dict) -> str:
    machine = hostname()
    now = datetime.now()
    alert = Alert(
        machine=machine,
        severity="warning",
        title="test alert — Huginn delivery check",
        body=("\n".join([
            f"Huginn — {machine} — {now.strftime('%Y-%m-%d %H:%M')}",
            "",
            "THIS IS A TEST. Nothing is wrong with your network.",
            "",
            "You asked Huginn to prove she can reach you. If you are reading",
            "this, one channel works. Check the console output to see which",
            "ones did not.",
        ])),
        raised_at=now.isoformat(timespec="seconds"),
        finding_ids=["admin_test"],
        finding_count=1,
    )

    # now=None would let quiet hours suppress the very test meant to prove
    # delivery. A test the operator asked for is always sent; quiet hours
    # govern unattended alerts, not deliberate checks.
    deliveries = deliver(alert, admin, now=now.replace(hour=12))

    lines = ["  DELIVERY TEST", "  " + "=" * 58, ""]
    for d in deliveries:
        mark = {"delivered": " ok ", "failed": "FAIL", "skipped": "skip",
                "suppressed": "held"}.get(d.outcome, "  ? ")
        target = f"  → {d.target}" if d.target else ""
        detail = f"  ({d.detail})" if d.detail else ""
        lines.append(f"   {mark}  {d.channel:9}{target}{detail}")

    carried = [d for d in deliveries if d.ok and d.channel != "journal"]
    lines.append("")
    if carried:
        lines.append("  " + summarize(deliveries))
        lines.append("")
        lines.append("  Now go and confirm it ARRIVED. A channel that reported")
        lines.append("  success and did not reach you is the failure this verb")
        lines.append("  exists to catch.")
    else:
        lines.append("  NOTHING REACHED A PERSON.")
        lines.append("  The alert is on disk and that is all. If the guard found")
        lines.append("  something tonight, you would not hear about it.")
    return "\n".join(lines)


def skill_admin(args: str, speaker: Any = None) -> str:
    """Show the registered administrator, or test delivery to them."""
    del speaker
    admin = load_admin()
    if (args or "").strip().lower().startswith("test"):
        return _test(admin)
    return _describe(admin)


def register(registry) -> None:
    registry.register(
        "admin",
        skill_admin,
        aliases=[
            "administrator", "who gets told", "alert config", "test alert",
            "beheerder",                                   # NL
            "administrateur",                              # FR
        ],
    )
