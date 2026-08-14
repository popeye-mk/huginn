"""Windows error-code decoder (spec §10).

Pure lookup over pattern_kb/error_codes.yaml. Deliberately requires no
snapshot and no collector: the entry point is a technician with a code
a user read to them over the phone.

Normalisation matters more than it looks. The same code reaches a
technician as `0x80070005`, `80070005`, `0X80070005`, or with stray
whitespace from a copy-paste. All of them resolve to one entry.

BSOD codes are conventionally written zero-padded to 8 digits
(0x0000007E) but users routinely type the short form (0x7e). Lookup
tries the literal form first, then the zero-padded one, so both work
without duplicating every entry in the YAML.
"""

import os
import re

import yaml

from resources import resource_path

# Hex codes as they appear inside event log free text, e.g.
# "failed to install the following update with error 0x80073D02:".
# Deliberately requires the 0x prefix and 8 digits: a bare 8-hex-digit
# string is far more often a GUID fragment or a handle than an error
# code, and a decoder that fires on those would be noise.
_CODE_IN_TEXT = re.compile(r"\b(0x[0-9a-fA-F]{8})\b")

CODES_PATH = resource_path("pattern_kb", "error_codes.yaml")


def load_codes(path=CODES_PATH):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def normalise(code):
    """'0X8007_0005 ' -> '0x80070005'. Returns None for empty input."""
    if code is None:
        return None
    cleaned = str(code).strip().lower().replace("_", "").replace(" ", "")
    if not cleaned:
        return None
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    return "0x" + cleaned


def _candidates(normalised):
    """The literal form, then the 8-digit zero-padded form."""
    body = normalised[2:]
    forms = [normalised]
    if len(body) < 8:
        forms.append("0x" + body.rjust(8, "0"))
    return forms


def decode(code, codes=None):
    """Returns a dict describing the code, or None if unknown.

    Unknown is a real answer here (§3.4 applied to lookups): inventing a
    plausible-sounding meaning for an unrecognised hex code is exactly
    the confident wrongness this tool is supposed to avoid.
    """
    codes = codes if codes is not None else load_codes()
    normalised = normalise(code)
    if not normalised:
        return None

    forms = _candidates(normalised)
    for category, entries in codes.items():
        for entry in entries:
            if normalise(entry["code"]) in forms:
                result = dict(entry)
                result["category"] = category
                return result
    return None


def render_decode(code, result):
    if result is None:
        return (
            f"Unknown code: {code}\n"
            "Not in the decoder's knowledge base. That is not the same as "
            "'harmless' — it means this tool has nothing useful to say about it.\n"
            "Search the exact code against Microsoft's documentation before acting."
        )

    label = {"windows_update": "Windows Update", "bsod": "Stop code (BSOD)"}.get(
        result["category"], result["category"]
    )

    lines = [f"{label}: {result['code']}"]
    if result.get("name"):
        lines.append(f"  {result['name']}")
    if result.get("meaning"):
        lines.append(f"  Means:  {result['meaning']}")
    lines.append(f"  Cause:  {result['cause']}")
    lines.append(f"  Next:   {result['next_step']}")
    return "\n".join(lines)


def scan_text(text, codes=None):
    """Find known error codes inside free text (spec §10).

    Event log messages routinely embed a hex code the user has no way to
    interpret. Cross-referencing them against the decoder is the
    "how did it know that?" moment §10 is after, and it costs one regex
    over text already collected.

    Only *known* codes are returned. An unrecognised hex string is left
    alone rather than reported as an undecodable finding — a report that
    lists every hex number it saw is noise, not diagnosis.
    """
    codes = codes if codes is not None else load_codes()
    seen, results = set(), []

    for match in _CODE_IN_TEXT.findall(text or ""):
        key = normalise(match)
        if key in seen:
            continue
        seen.add(key)
        decoded = decode(match, codes)
        if decoded:
            results.append(decoded)
    return results


def scan_snapshot(snapshot, codes=None):
    """Scan a snapshot's log entries for decodable error codes."""
    section = (snapshot.get("sections") or {}).get("logs") or {}
    if section.get("status") != "ok":
        return []

    entries = (section.get("data") or {}).get("entries") or []
    return scan_text(" ".join(str(e) for e in entries), codes)


def all_codes(codes=None):
    codes = codes if codes is not None else load_codes()
    out = []
    for category, entries in codes.items():
        for entry in entries:
            out.append((category, entry["code"], entry.get("name") or entry.get("meaning", "")))
    return sorted(out)
