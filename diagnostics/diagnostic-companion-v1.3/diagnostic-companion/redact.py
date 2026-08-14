"""--anon redaction (spec §4.3, §5).

"Redaction is tested like a security control, not a feature": every
collector's data must have an explicit, registered redaction decision
before it can appear in --anon output. A collector with no entry in
SECTION_REDACTORS is a bug (redact_snapshot raises), never a silent
pass-through — see test_redact.py's completeness test.

Policy actually implemented:
  - hostname                -> always masked (stable hash, so repeated
                                reports from the same machine can still
                                be recognised as the same machine
                                without revealing its name)
  - Wi-Fi SSID              -> always masked
  - public IP addresses     -> masked (gateway, DNS servers, ping
                                targets); private/loopback/link-local
                                addresses are kept, because they're
                                needed to actually troubleshoot a LAN
                                and don't identify the user the way a
                                public IP or hostname does — a
                                judgement call, recorded here and in
                                docs/DATA_INVENTORY.md, not an accident
  - log entry free text     -> best-effort pattern redaction of IPv4,
                                MAC addresses, email addresses, and
                                /home/<user> or C:\\Users\\<user> paths.
                                This is NOT exhaustive — free text can
                                contain anything — and that limitation
                                is stated plainly rather than implied
                                to be complete.
  - everything else numeric/structural (disk sizes, error counts,
    kernel version, SMART health, battery %, ...) -> kept; none of it
    identifies a person.
"""

import copy
import hashlib
import ipaddress
import re


def _mask(value, prefix):
    if not value:
        return value
    digest = hashlib.sha256(str(value).encode()).hexdigest()[:8]
    return f"{prefix}-{digest}"


def _is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # not a literal IP (e.g. a DHCP hostname) — not this function's job
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)


def _redact_ip(ip_str):
    if ip_str and _is_public_ip(ip_str):
        return _mask(ip_str, "ip")
    return ip_str


_LOG_PATTERNS = [
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), lambda m: _redact_ip(m.group(0)) or m.group(0)),
    (re.compile(r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b"), lambda m: _mask(m.group(0), "mac")),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), lambda m: _mask(m.group(0), "email")),
    (re.compile(r"(?:/home/|\\Users\\)([^/\\:\s]+)"), lambda m: m.group(0).replace(m.group(1), _mask(m.group(1), "user"))),
]


def redact_log_text(line):
    for pattern, replacer in _LOG_PATTERNS:
        line = pattern.sub(replacer, line)
    return line


def redact_system(data):
    return copy.deepcopy(data)  # nothing sensitive in system.data


def redact_network(data):
    out = copy.deepcopy(data)
    out["gateway"] = _redact_ip(data.get("gateway"))
    out["dns_servers"] = [_redact_ip(s) for s in (data.get("dns_servers") or [])]
    if out.get("gateway_ping"):
        out["gateway_ping"]["target"] = _redact_ip(data["gateway_ping"].get("target"))
    # public_ping.target is our own fixed probe address (1.1.1.1) — a
    # constant this tool chose to test connectivity with, not the
    # user's infrastructure, so it's deliberately left as-is.
    return out


def redact_disk(data):
    return copy.deepcopy(data)  # device paths / mountpoints aren't personal data


def redact_logs(data):
    out = copy.deepcopy(data)
    out["entries"] = [redact_log_text(line) for line in data.get("entries", [])]
    return out


def redact_battery(data):
    return copy.deepcopy(data)  # capacity/cycle counts aren't personal data


def redact_wifi(data):
    out = copy.deepcopy(data)
    for adapter in out.get("adapters", []):
        if adapter.get("ssid"):
            adapter["ssid"] = _mask(adapter["ssid"], "ssid")
    return out


def redact_smart(data):
    # No serial numbers collected yet — nothing to mask today. Add a
    # rule here the day a collector starts reading disk serials.
    return copy.deepcopy(data)


SECTION_REDACTORS = {
    "system": redact_system,
    "network": redact_network,
    "disk": redact_disk,
    "logs": redact_logs,
    "battery": redact_battery,
    "wifi": redact_wifi,
    "smart": redact_smart,
}


def redact_snapshot(snapshot):
    """Returns a redacted deep copy. Raises RuntimeError if any
    collector section in the snapshot has no registered redaction rule
    — an unredacted field must be an explicit choice, never an
    oversight (spec §4.3)."""
    redacted = copy.deepcopy(snapshot)
    redacted["hostname"] = _mask(snapshot.get("hostname"), "host")

    for section_id, section in redacted.get("sections", {}).items():
        if section.get("status") != "ok":
            continue  # no data present, nothing to redact
        if section_id not in SECTION_REDACTORS:
            raise RuntimeError(
                f"No redaction rule registered for collector '{section_id}' — "
                "add one to redact.py's SECTION_REDACTORS before this can ship "
                "in --anon output (spec §4.3: an unredacted field must be an "
                "explicit choice, never an oversight)."
            )
        section["data"] = SECTION_REDACTORS[section_id](section["data"])

    return redacted
