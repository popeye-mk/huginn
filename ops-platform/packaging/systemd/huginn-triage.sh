#!/usr/bin/env bash
# Scheduled triage — the wrapper the systemd timer runs.
#
# Runs `./ops triage` unattended so findings accumulate on their own.
# That accumulation is the whole point: the recall lines built at M2
# ("seen 9x on this machine since May") are only as useful as the
# history behind them, and a machine scanned once has no history.
#
# Deliberately quiet and safe:
# - never touches the network or the assistant; triage is the local
#   deterministic engines only
# - logs to the journal via stdout/stderr; the timer captures it
# - a failed run is logged and exits non-zero so `systemctl status`
#   shows red, but it does not retry-storm or alert
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

echo "[$(date -Is)] scheduled triage starting"
"$PLATFORM/ops" triage
echo "[$(date -Is)] scheduled triage done"
