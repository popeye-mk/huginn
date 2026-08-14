#!/usr/bin/env bash
# One entry point for Linux. Everything it uses lives in launchers/.
#
#     ./install-launcher.sh            install a desktop icon
#     ./install-launcher.sh --remove   remove it
exec "$(dirname "${BASH_SOURCE[0]}")/launchers/linux/install-desktop-entry.sh" "$@"
