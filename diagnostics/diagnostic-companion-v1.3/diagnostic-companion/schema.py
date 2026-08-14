"""
Shared snapshot schema (spec §4.3).

A snapshot is one JSON-serialisable dict:

{
  "schema_version": "0.1.0",
  "collected_at": "2026-07-20T10:00:00Z",
  "hostname": "...",
  "os": "linux" | "windows",
  "sections": {
    "<collector_id>": {
      "status": "ok" | "skipped" | "timeout" | "error",
      "reason": str | None,
      "duration_ms": int,
      "privilege_level": "unprivileged" | "elevated",
      "data": {...}
    },
    ...
  }
}

Every collector's output MUST go through build_envelope() so that
"absence is never health" (spec §3.4) is mechanically enforced rather
than left to each collector to remember.
"""

SCHEMA_VERSION = "0.1.0"

VALID_STATUSES = {"ok", "skipped", "timeout", "error"}


def build_envelope(status, reason, duration_ms, privilege_level, data):
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    return {
        "status": status,
        "reason": reason,
        "duration_ms": duration_ms,
        "privilege_level": privilege_level,
        "data": data or {},
    }
