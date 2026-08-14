#!/usr/bin/env bash
# Install a scheduled Huginn user timer. Run once, no root needed.
#
#   ./packaging/systemd/install-timer.sh              # triage (every 3h)
#   ./packaging/systemd/install-timer.sh patrol       # network guard (hourly)
#   ./packaging/systemd/install-timer.sh health       # codebase health (daily)
#   ./packaging/systemd/install-timer.sh --remove     # remove triage
#   ./packaging/systemd/install-timer.sh patrol --remove
#
# A USER timer (systemctl --user), not a system one: it runs as the
# operator, sees their session, and needs no sudo. It survives logout
# only if lingering is enabled — the script offers that at the end.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"
UNIT_DIR="$HOME/.config/systemd/user"

# First arg may name the timer (triage|patrol|health); default triage for
# back-compat with the installs that predate the others.
NAME="huginn-triage"
case "${1:-}" in
  health|triage|patrol) NAME="huginn-$1"; shift ;;
esac

if [ "${1:-}" = "--remove" ]; then
  systemctl --user disable --now "$NAME.timer" 2>/dev/null || true
  rm -f "$UNIT_DIR/$NAME.service" "$UNIT_DIR/$NAME.timer"
  systemctl --user daemon-reload 2>/dev/null || true
  echo "  removed. Findings already recorded are kept."
  exit 0
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "  systemd not found. On a non-systemd box, add this to crontab -e:"
  case "$NAME" in
    huginn-health) SCHED="0 7 * * *" ;;
    huginn-patrol) SCHED="0 * * * *" ;;
    *)             SCHED="0 */3 * * *" ;;
  esac
  echo "    $SCHED  $PLATFORM/packaging/systemd/$NAME.sh >> ~/$NAME.log 2>&1"
  exit 1
fi

mkdir -p "$UNIT_DIR"
# Rewrite %h-relative ExecStart to the REAL platform path, because the
# checkout is not always at ~/anora-ops/. (The product is Huginn; the
# CHECKOUT DIRECTORY is still named anora-ops and the units ship that
# default path — renaming the folder is a separate, deliberate step.)
sed "s#%h/anora-ops/ops-platform#$PLATFORM#g" \
    "$HERE/$NAME.service" > "$UNIT_DIR/$NAME.service"
cp "$HERE/$NAME.timer" "$UNIT_DIR/$NAME.timer"

systemctl --user daemon-reload
systemctl --user enable --now "$NAME.timer"

echo
case "$NAME" in
  huginn-health)
    echo "  installed and started. Daily the codebase-health check runs." ;;
  huginn-patrol)
    echo "  installed and started. Hourly the Network Guard patrols the LAN."
    echo
    echo "  ⚠ It RECORDS; it does not yet DELIVER. A finding at 03:00 goes to"
    echo "    the timeline and the journal, and notifies nobody. The alerting"
    echo "    path is chapter two item 2 — until it lands, read findings with"
    echo "    '$PLATFORM/ops timeline' or the Guard dashboard." ;;
  *)
    echo "  installed and started. Every 3 hours triage runs and records." ;;
esac
echo "  check it:   systemctl --user list-timers $NAME.timer"
echo "  run now:    systemctl --user start $NAME.service"
echo "  watch log:  journalctl --user -u $NAME.service -f"
echo
echo "  To keep it running while you are logged out:"
echo "    sudo loginctl enable-linger $USER"
echo "  (optional — without it the timer pauses when no session is open.)"
