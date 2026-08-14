#!/bin/sh
# Put netdiag on the desktop and in the applications menu.
#
# No sudo, nothing system-wide, nothing to uninstall but three files. This
# installs for THIS user only:
#
#   ~/.local/bin/netdiag           the tool itself
#   ~/.local/bin/netdiag-window    opens it in a terminal window
#   ~/.local/share/applications/   the menu entry
#   ~/Desktop/netdiag.desktop      the icon you asked for
#
#   ./install_desktop.sh              install
#   ./install_desktop.sh --uninstall  remove all of the above
set -e

SRC="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"
APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor/scalable/apps"

# Zorin/GNOME localises the Desktop folder name; ask instead of guessing, or
# an installer "succeeds" and puts the icon somewhere the user never looks.
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
[ -d "$DESKTOP_DIR" ] || DESKTOP_DIR="$HOME/Desktop"

if [ "$1" = "--uninstall" ]; then
  rm -f "$BIN/netdiag" "$BIN/netdiag-window" \
        "$APPS/netdiag.desktop" "$ICONS/netdiag.svg" \
        "$DESKTOP_DIR/netdiag.desktop"
  echo "Removed. Your saved baselines in ~/.netdiag are untouched —"
  echo "delete that folder too if you want a clean slate."
  exit 0
fi

[ -f "$SRC/netdiag_linux_amd64" ] || { echo "netdiag_linux_amd64 not found next to this script." >&2; exit 1; }

mkdir -p "$BIN" "$APPS" "$ICONS" "$DESKTOP_DIR"
install -m 0755 "$SRC/netdiag_linux_amd64" "$BIN/netdiag"
install -m 0644 "$SRC/netdiag.svg" "$ICONS/netdiag.svg"

# A launcher that finds a terminal itself. Terminal=true in a .desktop file
# depends on the desktop environment having a terminal registered, which is
# exactly the kind of thing that works on the machine you tested and fails on
# someone else's. Trying them in order is boring and reliable.
# The launcher uses the ABSOLUTE path, never a bare `netdiag`.
#
# The first version relied on PATH and failed with "sh: 1: netdiag: not found"
# the moment it was clicked: the terminal spawned from a desktop icon does not
# inherit the shell PATH that ~/.profile builds at login, and ~/.local/bin is
# often only added there conditionally. The installer already knows exactly
# where it put the binary, so asking PATH to find it again was a guess where a
# fact was available.
cat > "$BIN/netdiag-window" <<LAUNCHER
#!/bin/sh
# Open netdiag's guided menu in whatever terminal this machine has.
NETDIAG="$BIN/netdiag"
LAUNCHER
cat >> "$BIN/netdiag-window" <<'LAUNCHER'
[ -x "$NETDIAG" ] || NETDIAG="$(command -v netdiag 2>/dev/null)"
if [ -z "$NETDIAG" ]; then
  MSG="netdiag is not installed where this launcher expects it. Re-run install_desktop.sh."
  command -v zenity >/dev/null 2>&1 && zenity --error --text="$MSG" || echo "$MSG" >&2
  exit 1
fi
CMD=""$NETDIAG" menu; printf '\n  Press Enter to close this window. '; read x"
for t in gnome-terminal x-terminal-emulator konsole xfce4-terminal mate-terminal \
         tilix kitty alacritty foot xterm; do
  command -v "$t" >/dev/null 2>&1 || continue
  case "$t" in
    gnome-terminal|tilix) exec "$t" -- sh -c "$CMD" ;;
    konsole|xfce4-terminal|mate-terminal|x-terminal-emulator|xterm)
      exec "$t" -e sh -c "$CMD" ;;
    kitty|alacritty|foot) exec "$t" sh -c "$CMD" ;;
  esac
done
# No terminal at all: say so somewhere the user will see it.
if command -v zenity >/dev/null 2>&1; then
  zenity --error --text="No terminal emulator found. Run 'netdiag menu' from a shell."
fi
exit 1
LAUNCHER
chmod 0755 "$BIN/netdiag-window"

cat > "$APPS/netdiag.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Version=1.0
Name=netdiag
GenericName=Network Diagnostician
Comment=Find out what is wrong with this computer's network — read-only, changes nothing
Exec=$BIN/netdiag-window
Icon=$ICONS/netdiag.svg
Terminal=false
Categories=System;Network;Monitor;
Keywords=network;wifi;dns;slow;internet;diagnose;troubleshoot;
Actions=Scan;Selftest;Ticket;

[Desktop Action Scan]
Name=Check this computer now
Exec=$BIN/netdiag-window

[Desktop Action Selftest]
Name=Check netdiag itself
Exec=sh -c "$BIN/netdiag selftest; printf '\\n  Press Enter to close. '; read x"

[Desktop Action Ticket]
Name=Write a ticket to hand over
Exec=sh -c "$BIN/netdiag ticket; printf '\\n  Press Enter to close. '; read x"
DESKTOP
chmod 0755 "$APPS/netdiag.desktop"

cp "$APPS/netdiag.desktop" "$DESKTOP_DIR/netdiag.desktop"
chmod 0755 "$DESKTOP_DIR/netdiag.desktop"

# GNOME (so Zorin) refuses to run a desktop file it does not trust, and shows
# it as a text file instead. This is the step people usually miss.
if command -v gio >/dev/null 2>&1; then
  gio set "$DESKTOP_DIR/netdiag.desktop" metadata::trusted true 2>/dev/null || true
fi

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && \
  gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" 2>/dev/null || true

# An older netdiag installed system-wide (by install_linux.sh, with sudo) sits
# in /usr/local/bin and usually comes BEFORE ~/.local/bin on the PATH. Typing
# `netdiag` then runs the old one, and you spend an afternoon testing a build
# you did not install. This exact confusion cost a real test round, so the
# installer now looks for it and says so.
EXISTING="$(command -v netdiag 2>/dev/null || true)"
if [ -n "$EXISTING" ] && [ "$EXISTING" != "$BIN/netdiag" ]; then
  OLD_VER="$("$EXISTING" -version 2>/dev/null || echo unknown)"
  NEW_VER="$("$BIN/netdiag" -version 2>/dev/null || echo unknown)"
  echo
  echo "WARNING: another netdiag is earlier on your PATH and will win:"
  echo "    $EXISTING   ($OLD_VER)   <- what 'netdiag' runs"
  echo "    $BIN/netdiag   ($NEW_VER)   <- what was just installed"
  echo
  echo "  The desktop icon uses the NEW one regardless. To make the command"
  echo "  agree with the icon, remove the old install:"
  echo "      sudo rm $EXISTING"
  echo
fi

echo "Installed for $USER:"
echo "  desktop icon : $DESKTOP_DIR/netdiag.desktop"
echo "  menu entry   : search 'netdiag' in the applications menu"
echo "  command      : netdiag"
echo
echo "  Double-click the icon to open the guided menu — that is the whole"
echo "  interface. (Right-click shortcuts exist but most desktops only show"
echo "  them on a pinned taskbar icon; everything they do is in the menu.)"
echo

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "NOTE: $BIN is not on your PATH, so the 'netdiag' command will not work"
     echo "      from a terminal yet. The icon works regardless. To fix:"
     echo "        echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && . ~/.bashrc"
     echo ;;
esac

# Pings without sudo need one capability. Offered, never done silently: this
# is the only part of the install that touches anything privileged, and a
# tool that claims to be read-only should ask before it asks for a capability.
if command -v setcap >/dev/null 2>&1; then
  echo "Optional: ICMP pings currently need sudo. To let netdiag ping as you:"
  echo "  sudo setcap cap_net_raw+ep $BIN/netdiag"
  echo "(Without it, netdiag falls back to TCP probes and says so in the report.)"
fi
