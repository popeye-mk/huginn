#!/usr/bin/env bash
# ====================================================================
#  Launcher for the USB stick (Linux / macOS).
#
#  The Windows counterpart is RUN-DIAGNOSTIC.bat. This exists for the
#  same two reasons:
#
#    1. It is unmistakably "the thing to run" next to a binary, a
#       README and a pile of reports.
#    2. It cd's to its own directory first. Reports are written beside
#       the program, and running the binary from elsewhere by an
#       absolute path would otherwise leave the shell's working
#       directory somewhere unrelated.
#
#  Unlike Windows there is no reliable double-click story on Linux:
#  most file managers open .sh files in an editor rather than running
#  them, and .desktop launchers cannot resolve paths relative to
#  themselves, which breaks on removable media whose mount point
#  changes. Running this from a terminal is the honest answer.
# ====================================================================

set -u

# Resolve this script's own directory, following symlinks, so the
# launcher works whether it is called as ./run-diagnostic.sh, by
# absolute path, or through a symlink someone made for convenience.
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
HERE="$(cd -P "$(dirname "$SOURCE")" && pwd)"

cd "$HERE" || exit 1

if [ ! -f "./diag" ]; then
    echo
    echo "  The 'diag' program is missing from this folder."
    echo "  This USB stick is incomplete - see README.txt."
    echo
    exit 1
fi

# Removable media is frequently FAT32 or exFAT, neither of which stores
# the executable bit. Restore it rather than making the user work it
# out from a bare "Permission denied".
if [ ! -x "./diag" ]; then
    chmod +x "./diag" 2>/dev/null || true
fi

if [ ! -x "./diag" ]; then
    echo
    echo "  Cannot make 'diag' executable on this filesystem."
    echo
    echo "  The stick is probably mounted with 'noexec', which some"
    echo "  managed systems enforce for removable media. Copy the"
    echo "  folder to your home directory and run it from there:"
    echo
    echo "      cp -r \"$HERE\" ~/diagnostic-companion"
    echo "      cd ~/diagnostic-companion && ./diag"
    echo
    exit 1
fi

./diag "$@"
STATUS=$?

# Only pause on an early failure. The menu exits cleanly on its own,
# and a prompt after a normal quit is just noise.
if [ $STATUS -ne 0 ] && [ $STATUS -ne 130 ]; then
    echo
    read -r -p "  Press Enter to close... " _
fi

exit $STATUS
