#!/usr/bin/env bash
# Install the Huginn git hooks into this checkout's .git/hooks/.
#
# Hooks live in the repo (tools/hooks/) so they are versioned and reviewed;
# git only runs the copy under .git/hooks/, which is not tracked — so each
# checkout runs this once. Re-run it after the hook changes.
#
#     bash tools/hooks/install-hooks.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
DEST="$ROOT/.git/hooks"

mkdir -p "$DEST"
for hook in pre-commit; do
    cp "$HERE/$hook" "$DEST/$hook"
    chmod +x "$DEST/$hook"
    echo "  installed $hook -> $DEST/$hook"
done
echo "  done. The pre-commit checks now run on every code commit."
echo "  (bypass a single commit with: git commit --no-verify)"
