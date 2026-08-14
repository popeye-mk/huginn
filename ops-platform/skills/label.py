"""`label` skill — give a device on the LAN a friendly name by hand (G1f).

The census (G1) names devices by vendor, and the hostname probe (G1e) asks
each device its name — but a privacy-randomised phone or a bare IoT board
answers nothing, so it shows only "randomized MAC" or "[unknown]". This verb
lets the operator pin a name themselves:

    label 192.168.1.46 android tv box

Credential-free — it writes only to the local census baseline, never touches
the router or the network. The label is stored against the device's MAC, so
it follows the device across DHCP address changes, and it is kept separate
from the probed name, so a future census never overwrites it. Clear a label
by giving an empty one (`label 192.168.1.46 clear`).

Honest degrade: you can only label a device the census has actually seen —
labelling an IP that is not in the baseline says so and points you at
`census`, rather than silently inventing a record.
"""

import os
from typing import Any

from domains.census import load_baseline, save_baseline, set_label

_BASELINE = os.path.join("data", "census", "lan_baseline.json")
_CLEAR_WORDS = {"clear", "none", "-", "remove", "unlabel"}


def _parse(args: str):
    """Split the command into (ip, label). label '' means clear."""
    parts = (args or "").strip().split(None, 1)
    if not parts:
        return None, None
    ip = parts[0]
    text = parts[1].strip() if len(parts) > 1 else ""
    if text.lower() in _CLEAR_WORDS:
        text = ""
    return ip, text


def skill_label(args: str, speaker: Any = None) -> str:
    """Pin a friendly label on a LAN device: `label <ip> <name>`."""
    del speaker
    ip, text = _parse(args)
    if not ip:
        return ("Usage: label <ip> <name>   e.g. `label 192.168.1.46 tv box`\n"
                "       label <ip> clear     to remove a label")

    baseline = load_baseline(_BASELINE)
    if not baseline:
        return ("No census baseline yet — run `census` first, then label a "
                "device you saw. (Nothing was changed.)")

    mac = set_label(baseline, ip, text)
    if mac is None:
        return (f"No device at {ip} in the last census, so there is nothing to "
                f"label. Run `census` to see current devices, then use one of "
                f"their IPs. (Nothing was changed.)")

    save_baseline(_BASELINE, baseline)
    if text:
        return f"Labelled {ip} ({mac}) as \"{text}\". It will show on every future census."
    return f"Cleared the label on {ip} ({mac})."


def register(registry) -> None:
    registry.register(
        "label",
        skill_label,
        aliases=[
            "tag", "rename", "label device", "name device", "tag device",
            "noem apparaat",                                 # NL
            "nommer appareil",                               # FR
        ],
    )
