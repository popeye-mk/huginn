#!/usr/bin/env bash
# Close R7's honest gap: run the backup verifier against a REAL restic
# repository, on this machine, in about a minute.
#
#   ./tools/verify_backup_live.sh
#
# Builds a small throwaway repository, verifies it, then DELIBERATELY
# CORRUPTS A COPY and verifies that too — because a verifier that only
# recognises success has not been tested, it has been agreed with.
#
# Everything is created under a temp directory and removed at the end.
# Your own backups are never touched: this script never reads a
# repository it did not create, and RESTIC_REPOSITORY from your
# environment is explicitly ignored.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/.." && pwd)"
PY="$PLATFORM/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

if ! command -v restic >/dev/null 2>&1; then
  cat <<'MSG'
  restic is not installed.

    Debian/Ubuntu   sudo apt install restic
    Fedora          sudo dnf install restic
    Arch            sudo pacman -S restic
    Windows         winget install -e --id restic.restic
    Any             https://github.com/restic/restic/releases

  Nothing else is needed. This script creates its own repository.
MSG
  exit 2
fi

echo
echo "  R7 live verification — $(restic version | head -1)"
echo "  ==================================================================="

WORK="$(mktemp -d)"
# The repository is disposable and local, so the password is not a
# secret — but it still goes in a file rather than an argument, because
# that is the interface the engine uses and this run should exercise the
# real path, not a convenient one.
PASSFILE="$WORK/password"
echo "r7-live-verification-throwaway" > "$PASSFILE"
chmod 600 "$PASSFILE"

REPO="$WORK/repo"
DATA="$WORK/data"
# Ignore any repository the operator already has configured. A test that
# could point itself at real backups is a hazard, not a test.
unset RESTIC_REPOSITORY RESTIC_PASSWORD || true

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "  building a small dataset and repository under $WORK"
mkdir -p "$DATA"
for i in $(seq 1 20); do
  head -c 20000 /dev/urandom > "$DATA/file-$i.bin"
done
echo "the quick brown fox" > "$DATA/readable.txt"

restic -r "$REPO" --password-file "$PASSFILE" init >/dev/null
restic -r "$REPO" --password-file "$PASSFILE" backup "$DATA" >/dev/null
echo "  snapshot created"

STATUS=0

"$PY" "$HERE/verify_backup_live.py" healthy "$REPO" "$PASSFILE" || STATUS=1

# --- the run that matters ------------------------------------------------
# Corrupt a copy, never the original. Overwriting bytes inside a pack file
# is what silent bit-rot looks like from restic's side, and it is the
# failure mode restore testing exists to catch.
echo
echo "  corrupting a copy of the repository (bit-rot simulation)"
BROKEN="$WORK/broken"
cp -r "$REPO" "$BROKEN"
# restic writes pack files read-only (0444) on purpose — a repository is
# meant to be append-only, and that is a good thing which broke this
# script's first run with "dd: Permission denied". The copy is ours and
# disposable, so make it writable; the ORIGINAL is never touched.
chmod -R u+w "$BROKEN"

PACK="$(find "$BROKEN/data" -type f | head -1)"
if [ -z "$PACK" ]; then
  echo "  !! no pack file found to corrupt; damaged-repository run skipped"
  echo "  !! that is UNVERIFIED, not verified-clean"
  STATUS=1
elif ! printf 'CORRUPTED-BY-R7-LIVE-TEST' \
     | dd of="$PACK" bs=1 seek=64 conv=notrunc status=none; then
  # Report rather than abort. `set -e` killing the script here meant the
  # first run printed no verdict at all — the damaged case is the one
  # that matters, so its failure must be visible, not fatal.
  echo "  !! could not corrupt the copy; damaged-repository run NOT PERFORMED"
  echo "  !! that is UNVERIFIED, not verified-clean"
  STATUS=1
else
  echo "  corrupted $(basename "$PACK") at byte 64"
  "$PY" "$HERE/verify_backup_live.py" damaged "$BROKEN" "$PASSFILE" || STATUS=1
fi

echo
echo "  ==================================================================="
if [ "$STATUS" -eq 0 ]; then
  echo "  R7 LIVE: both runs behaved correctly against real restic."
  echo "  A healthy repo passed at file depth and refused to claim proof"
  echo "  of recovery; a corrupted repo was caught."
else
  echo "  R7 LIVE: something did not behave as claimed — see above."
  echo "  This is a real finding about the platform, not a flaky test."
fi
echo
exit "$STATUS"
