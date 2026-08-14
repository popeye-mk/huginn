#!/usr/bin/env bash
# Restart the Huginn GUI so code changes actually load.
#
# The problem this solves: the desktop icon runs gui-launch.sh, which refuses
# to start a second instance when one is already answering -- so after editing
# code it just reopens the browser to the STALE server still holding the old
# code in memory. Every code change this project has shipped needed a real
# kill-then-relaunch; this is that, in one command.
#
# Updated 2026-07-27: the process to stop is `runtime.app` (the native shell).
# It used to be `anora.py` -- the vendored fork, archived that day. Left
# unchanged, this script would have reported "none was running", then handed
# over to gui-launch, which would have found the old server still answering and
# reopened the browser to it: the exact stale-server trap it exists to prevent.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "  stopping any running Huginn (so the new code loads)..."
stopped=0
# The native shell, and the legacy fork name in case an old one is still up.
for pattern in 'runtime\.app' 'anora\.py'; do
  if pkill -f "$pattern" 2>/dev/null; then
    echo "  stopped ($pattern)."
    stopped=1
  fi
done
[ "$stopped" = 1 ] || echo "  none was running."

# Let the loopback port free before relaunching, or the fresh start dies on
# 'Address already in use' and the log blames the wrong thing.
sleep 2

echo "  relaunching..."
exec "$HERE/gui-launch.sh"
