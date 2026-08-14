#!/bin/sh
# Install netdiag as a normal command on this machine (Zorin/Ubuntu/any Linux).
#
# There is nothing to "install" in the usual sense: netdiag is ONE static
# binary with no dependencies, no config, no service, no registry. This script
# just puts it on your PATH and, optionally, grants the one capability that
# lets it ping without sudo. Uninstalling is `rm` of two paths.
#
#   sudo ./install_linux.sh            # install to /usr/local/bin
#   sudo ./install_linux.sh --uninstall
set -e

BIN_SRC="$(cd "$(dirname "$0")" && pwd)/netdiag_linux_amd64"
BIN_DST=/usr/local/bin/netdiag

if [ "$1" = "--uninstall" ]; then
  rm -f "$BIN_DST" /usr/share/applications/netdiag.desktop
  echo "Removed $BIN_DST"
  echo "Baselines and feedback (if any) are still in ~/.netdiag — remove that too if you want a clean slate."
  exit 0
fi

if [ "$(id -u)" != "0" ]; then
  echo "Run with sudo: sudo $0" >&2
  exit 1
fi
if [ ! -f "$BIN_SRC" ]; then
  echo "netdiag_linux_amd64 not found next to this script." >&2
  exit 1
fi

install -m 0755 "$BIN_SRC" "$BIN_DST"
echo "Installed $BIN_DST"

# Unprivileged ICMP: the kernel allows it for a GID range, but distros ship
# that range empty. Two honest options — the capability is the tidier one
# because it is scoped to this binary rather than to every process on the box.
if command -v setcap >/dev/null 2>&1; then
  if setcap cap_net_raw+ep "$BIN_DST" 2>/dev/null; then
    echo "Granted cap_net_raw to the binary — pings work without sudo."
  else
    echo "Could not set capabilities; netdiag will fall back to TCP probes"
    echo "or you can run it with sudo for ICMP."
  fi
else
  echo "setcap not present. Either run netdiag with sudo for ICMP, or allow"
  echo "unprivileged ping for your group:"
  echo "  sudo sysctl -w net.ipv4.ping_group_range='0 2147483647'"
fi

# Desktop entry, so netdiag can be started from the applications menu by
# people who never open a terminal.
if [ -f "$(dirname "$0")/netdiag.desktop" ]; then
  install -m 0644 "$(dirname "$0")/netdiag.desktop" /usr/share/applications/netdiag.desktop 2>/dev/null \
    && echo "Added to the applications menu (search for 'netdiag')."
fi

cat <<'EOF'

Done. Try:
  netdiag menu                 # guided menu — no commands to remember
  netdiag                      # passive scan of this machine
  netdiag why no-internet      # layer walk for a symptom
  netdiag baseline             # remember this location while it is healthy
  netdiag watch -duration 10m  # catch an intermittent fault as it happens
  netdiag ref ports            # offline cheat sheet

Nothing runs in the background; nothing was added to systemd.
EOF
