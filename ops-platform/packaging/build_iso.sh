#!/usr/bin/env bash
# Build the Windows verification ISO.
#
#   ./packaging/build_iso.sh [output.iso]
#
# The ISO carries a single zip rather than an unpacked tree. Two reasons,
# both learned the hard way: ISO9660 has a directory-depth limit that
# Diagnostic Companion's source tree exceeds, and optical media is
# read-only while the platform writes databases — so the payload has to
# be copied out before it can run regardless. A zip makes that copy one
# operation instead of a recursive walk across a slow mount.
#
# Requires: python3 (for pycdlib). No root, no loop mounts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/.." && pwd)"
ROOT="$(cd "$PLATFORM/.." && pwd)"

# --- build identity ------------------------------------------------------
# Every build gets a new number and a new filename. Reusing one filename
# cost a debugging round already: Windows will happily serve a cached
# mount of a disc you thought you had replaced, and neither the console
# output nor the report said which build produced it. Now the number is
# in the filename, in the volume label, in the console banner and in the
# report -- so a result can always be traced to the disc that produced it.
BUILD_FILE="$HERE/BUILD_NUMBER"
BUILD=$(( $(cat "$BUILD_FILE" 2>/dev/null || echo 0) + 1 ))
echo "$BUILD" > "$BUILD_FILE"
BUILD_ID=$(printf "b%03d" "$BUILD")
BUILD_DATE=$(date +%Y%m%d)
BUILD_TAG="${BUILD_ID}-${BUILD_DATE}"

OUT="${1:-$ROOT/huginn-verify-${BUILD_TAG}.iso}"
export HUGINN_VOLUME_ID="HUGINN_${BUILD_ID^^}"

echo "  build $BUILD_TAG"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

PAYLOAD="$STAGE/payload"
mkdir -p "$PAYLOAD"

echo "  staging payload..."

# --- the platform itself -------------------------------------------------
# Excludes are deliberate:
#   .venv  - a Linux virtualenv is worse than useless on Windows
#   ai/    - the Anora fork needs requests/numpy and a model download;
#            the smoke test does not, and shipping it would turn a
#            zero-dependency verification into a pip install
#   data/  - runtime state. Shipping a database would mean the report
#            described findings from a different machine.
#
# `data/knowledge/` is the exception and must be kept: the security KB is
# content, not state. Excluding all of `data/` shipped a disc whose
# grounding suite failed with the knowledge base missing - caught by the
# disc's own tests on the first build, which is exactly what they are
# for. The exclude is now specific rather than wholesale.
# `data/` is ALLOW-LISTED, not deny-listed. The deny list that used to be
# here named findings, devices, backup, secrets, census and snapshots -- and
# missed `data/admin.json`, which holds the ntfy TOPIC. That topic is the
# password: anyone holding it receives the operator's security alerts. It
# shipped on four discs before anyone looked inside one.
#
# A deny list is a promise to think of everything, renewed every time a file
# is added. An allow list fails the other way: a new content directory is
# missing from the disc, which a test notices, instead of a new credential
# being on it, which nothing did.
rsync -a \
  --exclude='.venv' --exclude='ai' \
  --include='data/' \
  --include='data/knowledge/***' \
  --include='data/feeds/***' \
  --include='data/oui/***' \
  --include='data/admin.example.json' \
  --exclude='data/*' \
  --exclude='*.db' \
  --exclude='__pycache__' --exclude='.git' --exclude='*.pyc' \
  "$PLATFORM/" "$PAYLOAD/ops-platform/"

# A disc is read-only and gets carried to other machines. Anything secret on
# it is secret forever and everywhere, so this refuses to build rather than
# warn: the previous version of this script had no check at all, and the
# leak was found by unzipping a finished disc rather than by building one.
echo "  checking the payload for secrets..."
LEAKS=""
for forbidden in "data/admin.json" "data/OWNER.json" "data/secrets" \
                 "data/census" "data/findings" "data/devices"; do
  [ -e "$PAYLOAD/ops-platform/$forbidden" ] && LEAKS="$LEAKS $forbidden"
done
# Any JSON holding a live ntfy topic or a password. Restricted to .json on
# purpose: a first version scanned everything and flagged
# tools/test_admin_settings.py, whose fixtures contain a made-up topic. A
# guard that cries wolf on its own test data gets commented out within a
# week, and then it is not a guard.
while IFS= read -r hit; do
  LEAKS="$LEAKS ${hit#$PAYLOAD/ops-platform/}"
done < <(find "$PAYLOAD/ops-platform" -name '*.json' \
           ! -name 'admin.example.json' -print0 2>/dev/null \
         | xargs -0 -r grep -lE '"(topic|password)"[[:space:]]*:[[:space:]]*"[^"]+"' \
           2>/dev/null || true)

if [ -n "$LEAKS" ]; then
  echo
  echo "  BUILD REFUSED — these would have shipped on a read-only disc:"
  for f in $LEAKS; do echo "    $f"; done
  echo
  echo "  A disc travels. A credential on one is disclosed permanently."
  exit 1
fi

# --- Diagnostic Companion (source; it runs as `python cli.py`) -----------
DC_SRC="$ROOT/diagnostics/diagnostic-companion-v1.3/diagnostic-companion"
DC_DST="$PAYLOAD/diagnostics/diagnostic-companion-v1.3/diagnostic-companion"
mkdir -p "$DC_DST"
# `.venv` matters as much here as it does for the platform, and was
# missed the first time: 5,910 files of a *Linux* virtualenv, 138 MB
# uncompressed, shipped on a disc whose only job is to run on Windows.
# Harmless but wrong - and worse than wrong, it makes the disc look like
# it has dependencies installed when it deliberately has none.
rsync -a \
  --exclude='.venv' --exclude='venv' \
  --exclude='build' --exclude='dist' --exclude='__pycache__' \
  --exclude='.git' --exclude='*.pyc' --exclude='*.pyo' \
  "$DC_SRC/" "$DC_DST/"

# --- netdiag (Windows binary only) ---------------------------------------
# The Linux binary and the Go source are 20MB of dead weight on a disc
# whose only job is to run on Windows.
ND_SRC="$ROOT/network/netdiag_v1"
ND_DST="$PAYLOAD/network/netdiag_v1"
mkdir -p "$ND_DST"
cp "$ND_SRC/netdiag_windows_amd64.exe" "$ND_DST/"
[ -d "$ND_SRC/kb" ] && cp -r "$ND_SRC/kb" "$ND_DST/"

echo "  compressing payload..."
ISO_ROOT="$STAGE/iso"
mkdir -p "$ISO_ROOT"
( cd "$PAYLOAD" && zip -qr "$ISO_ROOT/huginn-payload.zip" . )

cp "$HERE/VERIFY.cmd" "$ISO_ROOT/"
cp "$HERE/verify_windows.py" "$ISO_ROOT/"
cp "$HERE/README-ISO.txt" "$ISO_ROOT/README.txt"
cp "$HERE/HYPERV-BOOT-TEST.txt" "$ISO_ROOT/"

# The build stamp travels on the disc, so the report can name the disc
# that produced it rather than leaving that to whoever files it.
printf '%s\n' "$BUILD_TAG" > "$ISO_ROOT/BUILD.txt"

echo "  writing ISO..."
python3 "$HERE/write_iso.py" "$ISO_ROOT" "$OUT"

echo
echo "  ISO:  $OUT"
ls -lh "$OUT" | awk '{print "  size: " $5}'
