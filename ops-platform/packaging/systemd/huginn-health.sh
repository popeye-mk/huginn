#!/usr/bin/env bash
# Scheduled codebase-health check — the wrapper the systemd timer runs (B3).
#
# Runs the fast structural guards + the answer benchmark on a schedule, so a
# regression that slipped the pre-commit hook — or an uncommitted mess piling
# up — is SEEN, not discovered at the next release.
#
# Quiet and safe, like the triage wrapper:
# - reads the tree, runs the test scripts + git + the benchmark; no network
# - logs the report to the journal via stdout
# - exits non-zero on regression so `systemctl --user status huginn-health`
#   shows red; it does not retry-storm. Add an `OnFailure=` unit if you want
#   it mailed via your own alert channel.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

PY="$PLATFORM/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

echo "[$(date -Is)] codebase health starting"
"$PY" "$PLATFORM/tools/codebase_health.py"
rc=$?
echo "[$(date -Is)] codebase health done (exit $rc)"
exit $rc
