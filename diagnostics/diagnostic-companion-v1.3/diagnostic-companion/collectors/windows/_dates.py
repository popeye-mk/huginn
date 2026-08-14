"""PowerShell date parsing (spec §4.1).

`ConvertTo-Json` serialises a DateTime differently depending on the
PowerShell major version, which is why `windows/system.py` originally
shipped without uptime rather than guessing:

  PowerShell 5.1  ->  "/Date(1784538433261)/"   .NET epoch milliseconds
  PowerShell 7.x  ->  "2026-07-20T09:07:13.261+00:00"  ISO 8601

A real capture from Windows 11 Pro (build 26200, PowerShell 5.1.26100)
confirmed the first form — see tests/golden/win11_26200_ps51.json.
Both are handled here rather than assuming whichever the capture
machine happened to run, because 5.1 and 7.x coexist on real estates
and `_powershell.py` prefers `pwsh` when it is installed.

Returns None on anything unrecognised. A wrong timestamp is worse than
an absent one: absence is visible and honest, a silently wrong date
gets used to reason about when a problem started (§3.4).
"""

import re
from datetime import datetime, timezone

# "/Date(1784538433261)/" and the escaped "\/Date(...)\/" JSON emits.
# The optional trailing offset ("/Date(1784538433261+0200)/") appears on
# some locales and is ignored: the epoch part is already UTC.
_MS_EPOCH = re.compile(r"^\\?/Date\((-?\d+)(?:[+-]\d{4})?\)\\?/$")


def parse_ps_datetime(value):
    """PowerShell DateTime (either serialisation) -> aware UTC datetime, or None."""
    if value is None:
        return None

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        return _from_ms(value)

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    match = _MS_EPOCH.match(text)
    if match:
        return _from_ms(int(match.group(1)))

    # PowerShell 7 / any ISO 8601 producer. Python 3.10's fromisoformat
    # does not accept a trailing "Z", so normalise it first.
    try:
        return _ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError:
        return None


def _from_ms(milliseconds):
    try:
        return datetime.fromtimestamp(milliseconds / 1000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _ensure_utc(dt):
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def to_iso(value):
    """PowerShell DateTime -> 'YYYY-MM-DDTHH:MM:SS+00:00', or the input unchanged.

    Returning the original on failure keeps a log line readable even
    when its timestamp is in a shape nobody anticipated — losing the
    entry entirely would be a worse outcome than an ugly timestamp.
    """
    parsed = parse_ps_datetime(value)
    return parsed.isoformat(timespec="seconds") if parsed else value
