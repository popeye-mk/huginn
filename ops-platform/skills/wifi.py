"""`wifi` skill — the radios in earshot, and which of them you trust.

    wifi                  what is broadcasting, and anything unconfirmed
    wifi trust            confirm every radio currently serving YOUR SSID
    wifi trust <BSSID>    confirm one radio
    wifi forget <BSSID>   withdraw trust from one radio

Detection is against a **confirmed list of BSSIDs**, not against the SSID.
That is not fussiness — the operator's own network has SIX legitimate
BSSIDs (three dual-band access points in a mesh), so "known SSID on an
unknown BSSID" would have fired on his own equipment every hour. An alert
that cries wolf hourly is an alert nobody reads.

Nothing here transmits: the scan is read from NetworkManager's cache with
`--rescan no`. A stale or unreadable scan is reported as unchecked, never
as "no rogue access points found".
"""

from typing import Any

from domains.wifi import (
    assess, forget, learn, load_baseline, save_baseline, unchecked,
)
from engines.wifi_scan import is_available, read_radios, read_radios_sampled
from platform_support import hostname

_load = load_baseline
_save = save_baseline


def _current_ssid(radios) -> str:
    for radio in radios or []:
        if radio.in_use:
            return radio.ssid
    return ""


def _render_scan(radios, baseline, findings) -> str:
    lines = ["  WI-FI — RADIOS IN EARSHOT", "  " + "=" * 58]
    trusted_total = sum(len(v) for v in baseline.values())
    lines.append(f"  {len(radios)} radio(s) heard; {trusted_total} confirmed as yours.")
    lines.append("")

    for radio in sorted(radios, key=lambda r: (-r.signal, r.ssid)):
        name = radio.ssid or "(hidden)"
        mark = " "
        if radio.ssid in baseline:
            known = radio.bssid.upper() in {b.upper() for b in baseline[radio.ssid]}
            mark = "." if known else "!"
        used = " *" if radio.in_use else "  "
        lines.append(f"   {mark}{used} {name:<20} {radio.bssid}  "
                     f"{radio.band:<7} ch{radio.channel:<4} {radio.signal:>3}  "
                     f"{radio.security or 'open'}")

    lines.append("")
    lines.append("   * = connected   . = confirmed yours   ! = UNCONFIRMED on your SSID")

    if findings:
        lines += ["", f"  {len(findings)} finding(s):"]
        for f in findings:
            lines.append(f"   ! [{f.severity}] {f.message}")
            lines.append(f"       -> {f.suggested_action}")
    elif baseline:
        lines += ["", "  Every radio serving your networks is one you confirmed.",
                  "  That is not a guarantee: a twin can copy a MAC as easily as",
                  "  a name. It means nothing NEW has appeared."]
    return "\n".join(lines)


def _do_trust(args: str, radios, baseline) -> str:
    target = args.strip().upper()
    if target and ":" in target:
        match = [r for r in radios if r.bssid.upper() == target]
        if not match:
            return (f"  {target} is not in earshot right now. Nothing was "
                    "confirmed — trusting a radio you cannot hear would be "
                    "trusting a name, not a thing.")
        updated = baseline
        for radio in match:
            updated = learn([radio], updated)
        saved = _save(updated)
        return (f"  Confirmed {target} for \"{match[0].ssid}\"."
                if saved else "  Could NOT save the baseline. Nothing confirmed.")

    ssid = _current_ssid(radios)
    if not ssid:
        return ("  Not connected to any network, so there is no obvious SSID "
                "to confirm. Name one radio explicitly: wifi trust <BSSID>")

    before = len(baseline.get(ssid, []))
    updated = learn(radios, baseline, ssid=ssid)
    if not _save(updated):
        return "  Could NOT save the baseline. Nothing confirmed."
    added = len(updated.get(ssid, [])) - before

    lines = [f"  Confirmed {added} new radio(s) for \"{ssid}\" "
             f"({len(updated[ssid])} total):", ""]
    for bssid in updated[ssid]:
        lines.append(f"    {bssid}")
    lines += [
        "",
        "  ⚠ WHATEVER WAS IN EARSHOT IS NOW TRUSTED. If a twin was already",
        "    running when you ran this, it has just been confirmed as yours",
        "    and will never be reported. Check these against the labels on",
        "    your own access points, and `wifi forget` anything you do not",
        "    recognise. This is the one moment that judgement is required.",
        "",
        "  Radios out of earshot were NOT confirmed. An access point in a far",
        "  room is invisible from here and will be reported as unconfirmed the",
        "  first time you carry this machine near it — run `wifi trust` again",
        "  there. Confirming accumulates; it never replaces.",
    ]
    return "\n".join(lines)


def skill_wifi(args: str, speaker: Any = None) -> str:
    """Show radios in earshot; confirm or withdraw trust."""
    del speaker
    args = (args or "").strip()

    if not is_available():
        return ("Neither nmcli nor iw is available, so no radio could be "
                "read. This is not 'no rogue access point found' — it is "
                "nothing checked.")

    # `trust` writes a permanent decision, so it samples: a single read can
    # catch the cache mid-rescan and confirm one radio out of six. Reading
    # is cheap and passive; a wrong baseline is neither.
    wants_trust = args.lower().startswith("trust")
    radios = read_radios_sampled() if wants_trust else read_radios()
    if radios is None:
        return ("The Wi-Fi scan could not be read. Not an all-clear: no "
                "radio was checked. (If this machine has no Wi-Fi, that is "
                "the answer — but it is still not a clean bill of health.)")

    baseline = _load()

    if args.lower().startswith("trust"):
        return _do_trust(args[5:], radios, baseline)

    if args.lower().startswith("forget"):
        target = args[6:].strip().upper()
        if not target:
            return "  Which radio? Usage: wifi forget <BSSID>"
        updated = forget(baseline, target)
        if updated == baseline:
            return f"  {target} was not in the confirmed list. Nothing changed."
        return (f"  Withdrew trust from {target}. It will be reported as "
                "unconfirmed from the next scan."
                if _save(updated) else "  Could NOT save. Nothing changed.")

    findings = assess(radios, baseline, hostname())
    text = _render_scan(radios, baseline, findings)
    for reason in unchecked(radios, baseline):
        text += f"\n\n  NOT CHECKED: {reason}."
    return text


def register(registry) -> None:
    registry.register(
        "wifi",
        skill_wifi,
        aliases=[
            "wireless", "evil twin", "rogue ap", "access points", "radios",
            "draadloos", "valse ap",                        # NL
            "sans-fil", "faux point d'acces",               # FR
        ],
    )
