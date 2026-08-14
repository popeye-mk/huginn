#!/usr/bin/env bash
# ====================================================================
#  install.sh — install Huginn on a Linux desktop.
#
#  The whole job in one run:
#    1. make sure Python 3.8+ is present (offers to install it);
#    2. offer the two OPTIONAL external tools (nmap, numpy);
#    3. install the app icon + GUI launcher (packaging/desktop);
#    4. offer to schedule the hourly patrol (a user systemd timer).
#
#  No root for Huginn itself — it installs into your own profile and
#  watches a LAN it can already see. Root is asked for ONLY if you let
#  it install a missing system package, and it says so first.
#
#  Huginn has NO Python dependencies; it runs on the standard library
#  alone. "Dependencies" here means Python itself, plus two optional
#  tools it works without and reports as absent when missing.
# ====================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="$(cd "$HERE/../.." && pwd)"

echo
echo "  Huginn — Linux install"
echo "  ============================================================"

# --- 1. Python -------------------------------------------------------
# Checked first for the same reason the Windows installer does: files and
# a timer for an interpreter that is not there fail silently every hour.
py_ok() { command -v python3 >/dev/null 2>&1 && \
          python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,8) else 1)'; }

detect_pm() {
  for pm in apt-get dnf pacman zypper; do
    command -v "$pm" >/dev/null 2>&1 && { echo "$pm"; return; }
  done
}

if py_ok; then
  echo "  python:      $(command -v python3)  ($(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])'))"
else
  echo "  Python 3.8+ was not found."
  PM="$(detect_pm)"
  if [ -n "$PM" ]; then
    read -r -p "  Install it now with sudo $PM? [y/N] " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
      case "$PM" in
        apt-get) sudo apt-get update && sudo apt-get install -y python3 ;;
        dnf)     sudo dnf install -y python3 ;;
        pacman)  sudo pacman -S --noconfirm python ;;
        zypper)  sudo zypper install -y python3 ;;
      esac
    fi
  fi
  py_ok || { echo "  Still no usable Python 3.8+. Install it and re-run."; exit 1; }
fi

# --- 2. optional external tools -------------------------------------
echo
echo "  Optional tools (Huginn runs without them, and says so when absent):"
echo "    - nmap : a faster LAN sweep and port scan"
echo "    - numpy: semantic search over past findings"
read -r -p "  Install these two now? [y/N] " wantopt
if [[ "$wantopt" =~ ^[Yy]$ ]]; then
  PM="$(detect_pm)"
  if [ -n "$PM" ] && ! command -v nmap >/dev/null 2>&1; then
    echo "  installing nmap (sudo $PM)..."
    case "$PM" in
      apt-get) sudo apt-get install -y nmap ;;
      dnf)     sudo dnf install -y nmap ;;
      pacman)  sudo pacman -S --noconfirm nmap ;;
      zypper)  sudo zypper install -y nmap ;;
    esac || echo "  (nmap skipped — Huginn falls back to socket probes and says so)"
  fi
  echo "  installing numpy into your user site..."
  python3 -m pip install --user numpy 2>/dev/null \
    || echo "  (numpy skipped — semantic recall degrades to substring, and says so)"
fi

# --- 3. prove it runs, then install the icon ------------------------
echo
echo "  checking the platform runs here before installing anything..."
if ! ( cd "$PLATFORM" && python3 tools/ops.py --help >/dev/null 2>&1 ); then
  echo "  FAILED: the platform did not run. Nothing installed."
  exit 1
fi
echo "  ok."

echo
echo "  installing the app icon and launcher..."
bash "$HERE/../desktop/install-desktop.sh"

# --- 4. optional hourly patrol --------------------------------------
echo
read -r -p "  Schedule the hourly Network-Guard patrol (user systemd timer)? [y/N] " wanttimer
if [[ "$wanttimer" =~ ^[Yy]$ ]]; then
  if [ -x "$PLATFORM/packaging/systemd/install-timer.sh" ]; then
    bash "$PLATFORM/packaging/systemd/install-timer.sh" patrol
  else
    echo "  note: install-timer.sh not found; skipping the timer."
  fi
fi

echo
echo "  ============================================================"
echo "  Done. Find 'Huginn' in your app menu and on the Desktop."
echo "  If the desktop icon says untrusted: right-click -> Allow Launching."
