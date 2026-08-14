#!/usr/bin/env bash
# One-command release gate: verify everything, then — only if green — rebuild
# the verification disc.
#
#   bash tools/release.sh            full release: verify + build a fresh disc
#   bash tools/release.sh --dry-run  verify only; report what it WOULD build
#
# The build runs LAST and only after every check passes: a disc that captures
# a failing state is worse than no disc. Each step is fatal on failure, and a
# check that cannot run is a failure, never a silent skip — the same refusal
# the product itself is built on.
#
# Steps:
#   1. ops-platform battery — every tools/test_*.py green
#   2. verification disc — packaging/build_iso.sh (bumps BUILD_NUMBER)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ANCHOR_FLOOR=36
DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1

hr(){ printf '  %s\n' "===================================================================="; }
step(){ echo; echo "== $1 =="; }
die(){ echo; echo "  ✗ RELEASE ABORTED: $1"; exit 1; }

# 1 — ops-platform battery -------------------------------------------------
step "1/2  ops-platform battery"
bad=0
# Gate on exit code, not output: every suite exits non-zero on failure
# (asserts raise; test_architecture sys.exits), so a trailing status print
# can never be misread as a fail — and a real failure can never be missed.
for t in tools/test_*.py; do
    if python3 "$t" >/tmp/huginn-release.log 2>&1; then
        printf '  ok   %s\n' "$(basename "$t")"
    else
        printf '  FAIL %s\n' "$(basename "$t")"
        tail -4 /tmp/huginn-release.log | sed 's/^/       /'
        bad=1
    fi
done
[ "$bad" = 0 ] || die "an ops-platform suite failed"

# 2 — (retired) the fork suite ran here until 2026-07-26, when the vendored
# Anora fork was archived: the platform is standalone, so there is no second
# suite to gate on.

# 3 — (retired) the memory benchmark gated answer quality until 2026-07-26,
# when answering was removed: Huginn runs verbs, she does not answer
# questions, so there is no answer quality to regress.

# 4 — build the disc (only now that everything is green) -------------------
step "2/2  verification disc"
if [ "$DRY_RUN" = 1 ]; then
    next="$(( $(cat packaging/BUILD_NUMBER 2>/dev/null || echo 0) + 1 ))"
    echo "  (dry-run) all checks passed — would build b$(printf '%03d' "$next")."
    echo
    hr; echo "  ✓ DRY-RUN GREEN — verified, no disc built."; hr
    exit 0
fi
bash packaging/build_iso.sh || die "disc build failed"

echo
hr
echo "  ✓ RELEASE READY — everything verified and a fresh disc built."
echo "  Last step is yours: mount the ISO on a clean Windows box and run"
echo "  VERIFY.cmd — confirm 23/23, and the build tag traces to this disc."
hr
