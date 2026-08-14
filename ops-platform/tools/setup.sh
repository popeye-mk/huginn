#!/usr/bin/env bash
# Set up the ops platform's Python environment.
#
# Handles the three things that bite on a modern Ubuntu:
#   - PEP 668 ("externally-managed-environment") — we use a venv rather
#     than --break-system-packages, because breaking the system Python
#     to install a 2 GB ML library is a bad trade on a machine you care
#     about.
#   - `python` not existing — Ubuntu ships `python3` only.
#   - python3-venv sometimes being absent on a minimal install.
#
# Safe to re-run; skips what is already done.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
VENV="$ROOT/.venv"

echo "  Ops Platform setup"
echo "  ------------------"
echo "  Project: $ROOT"
echo

# --- 1. python3 present? --------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "  ERROR: python3 not found. Install it first:"
    echo "    sudo apt install python3 python3-venv"
    exit 1
fi
echo "  python3: $(python3 --version)"

# --- 2. venv module present? ---------------------------------------------
if ! python3 -c "import venv" >/dev/null 2>&1; then
    echo
    echo "  The venv module is missing. Install it, then re-run this script:"
    echo "    sudo apt install python3-venv"
    exit 1
fi

# --- 3. create the venv --------------------------------------------------
if [ -d "$VENV" ]; then
    echo "  venv:    already exists ($VENV)"
else
    echo "  venv:    creating..."
    python3 -m venv "$VENV"
fi

# shellcheck disable=SC1091
source "$VENV/bin/activate"
python -m pip install --upgrade pip --quiet

# --- 4. dependencies -----------------------------------------------------
echo
echo "  Installing dependencies (torch is ~2 GB — this takes a while)."
echo "  Trying CPU-only torch first: ~200 MB instead of ~2 GB."
echo

if pip install torch --index-url https://download.pytorch.org/whl/cpu --quiet 2>/dev/null; then
    echo "  torch:   CPU-only build installed"
else
    echo "  torch:   CPU index unreachable, falling back to the default build"
fi

pip install sentence-transformers faiss-cpu --quiet

# The Anora fork needs its own runtime deps (requests, httpx, ...).
# Installing only the ML libraries leaves imports failing in a way that
# looks like a code bug rather than a missing dependency.
if [ -f "$ROOT/requirements.txt" ]; then
    echo "  deps:    installing requirements.txt"
    pip install -r "$ROOT/requirements.txt" --quiet
fi

echo
echo "  ------------------------------------------------------------"
echo "  Done. Activate the environment in any new shell with:"
echo
echo "      source $VENV/bin/activate"
echo
echo "  Then verify R1:"
echo
echo "      python tools/test_memory_status.py"
echo
echo "  Expect the last line to read:  memory: faiss-persistent, 2241 entries"
echo "  ------------------------------------------------------------"
