"""Windows logs collector (spec §4.1) — Error/Critical entries from the
System event log via Get-WinEvent.

Unverified against a real Windows box — see collectors/windows/_powershell.py.

**`error_count` is counted, not inferred from the sample.** An earlier
version returned `len(entries)` where entries was capped at 20 by
`-MaxEvents`, which silently pinned error_count to at most 20 on
Windows. Two KB rules read this field: `high_error_log_volume` fires
above 10 and `severe_error_log_volume` above 100 — the second could
never fire on Windows at all, and the first saturated instead of
reflecting reality. Cross-platform rules require the fields underneath
them to mean the same thing on both platforms, so the script now counts
the full matching set and returns a bounded *sample* of entries
separately.

The try/catch exists because Get-WinEvent throws (rather than returning
empty) when no events match, which would otherwise look like a
collector failure on a genuinely healthy machine.
"""

import json
import re

from collectors.windows._dates import to_iso
from collectors.windows._powershell import run_powershell

MAX_ENTRIES = 20

# Window matches the Linux collector's intent ("recent"), stated
# explicitly here so the two platforms are comparable rather than
# coincidentally similar.
WINDOW_HOURS = 24

PS_COMMAND = f"""
try {{
  $since = (Get-Date).AddHours(-{WINDOW_HOURS})
  $all = @(Get-WinEvent -FilterHashtable @{{LogName='System';Level=1,2;StartTime=$since}} -ErrorAction Stop)
  $sample = $all | Select-Object -First {MAX_ENTRIES} |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message
  [PSCustomObject]@{{
    ErrorCount = $all.Count
    WindowHours = {WINDOW_HOURS}
    Entries = @($sample)
  }} | ConvertTo-Json -Compress -Depth 4
}} catch {{
  '{{"ErrorCount":0,"WindowHours":{WINDOW_HOURS},"Entries":[]}}'
}}
""".strip()


# PowerShell subprocess timeout. Must stay BELOW this collector's outer
# timeout in cli.py: the outer wrapper is a thread, and a thread timeout
# cannot kill a running subprocess. If the outer fires first, the query
# is abandoned rather than terminated and keeps running in the
# background. Enforced by tests/test_timeouts.py.
PS_TIMEOUT_S = 15


def parse(raw_json):
    obj = json.loads(raw_json)

    # Backward tolerance: an earlier build emitted a bare array of
    # entries with no envelope. Golden captures taken with that build
    # should still parse rather than becoming unreadable. From that
    # shape the true count is unrecoverable, so len() is the best
    # available answer and the sample size is all we can report.
    if isinstance(obj, list):
        obj = {"ErrorCount": len(obj), "WindowHours": None, "Entries": obj}

    # ConvertTo-Json collapses a single-element array to a bare object;
    # @() in the script guards the common case, but a snapshot captured
    # by an older build may still have the collapsed shape.
    rows = obj.get("Entries") or []
    if isinstance(rows, dict):
        rows = [rows]

    entries = []
    for row in rows:
        # Event log messages contain CRLF and run-on whitespace; a real
        # capture produced "terminated with the following error:   The
        # device is not ready." Collapse to single spaces so one entry
        # is one readable line.
        message = re.sub(r"\s+", " ", (row.get("Message") or "")).strip()[:200]

        # PowerShell 5.1 serialises DateTime as /Date(epoch_ms)/, which
        # is unreadable in a report. See collectors/windows/_dates.py.
        timestamp = to_iso(row.get("TimeCreated"))

        entries.append(
            f"{timestamp} [{row.get('LevelDisplayName')}] "
            f"{row.get('ProviderName')}: {message}"
        )

    return {
        # The true count over the window — NOT len(entries), which is a
        # capped sample. See module docstring.
        "error_count": obj.get("ErrorCount", 0),
        "window_hours": obj.get("WindowHours", WINDOW_HOURS),
        "entries": entries[:MAX_ENTRIES],
    }


def collect():
    raw = run_powershell(PS_COMMAND, timeout_s=PS_TIMEOUT_S)
    return parse(raw)
