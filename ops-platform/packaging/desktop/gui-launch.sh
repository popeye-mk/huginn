#!/usr/bin/env bash
# Open the Huginn GUI — the native shell serving console.html.
#
# Runs `python3 -m runtime.app`: the platform's own registry + router +
# loopback server. Until 2026-07-26 this booted the vendored Anora fork
# (`anora.py`) and had to chdir into it, wait 90s for an embedding model, and
# talk https to a self-signed cert. The fork is archived; none of that applies.
# The native shell starts in well under a second and binds plain http on
# loopback — no cert to trust, no model to load.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

# 8790: the native shell's default (the fork used 8788, the operator's other
# Anora project 8787 — all three can coexist).
PORT="${HUGINN_PORT:-8790}"
URL="http://127.0.0.1:$PORT"
LOG="$HOME/.local/state/huginn"
mkdir -p "$LOG"

PY="$PLATFORM/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

answers() { curl -s -o /dev/null --max-time 2 "$URL"; }
running() { pgrep -f 'runtime\.app' >/dev/null; }

if ! answers; then
  if running; then
    echo "  Huginn is already starting -- waiting for it"
  else
    echo "  starting Huginn (log: $LOG/server.log)"
    ( cd "$PLATFORM" && nohup "$PY" -m runtime.app >> "$LOG/server.log" 2>&1 & )
  fi
  # 20s is generous for a stdlib server with no model to load; the old 90s
  # existed only because the fork booted FAISS first.
  for _ in $(seq 1 20); do
    answers && break
    sleep 1
  done
fi

# No terminal assumed from here on. The desktop entry runs this with
# Terminal=false -- the previous Terminal=true crashed before the
# window appeared on desktops without a registered terminal handler.
# Errors go to a notification and the log, not to a read prompt that
# would die instantly with no tty attached.
tell() {
  notify-send "Huginn" "$1" 2>/dev/null \
    || zenity --warning --text="$1" 2>/dev/null \
    || echo "$1"
}

if answers; then
  xdg-open "$URL" >/dev/null 2>&1 || sensible-browser "$URL" || true
else
  tell "Huginn did not answer after 20s. See: $LOG/server.log"
fi
