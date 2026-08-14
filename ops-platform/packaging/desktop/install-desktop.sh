#!/usr/bin/env bash
# Install the Huginn icon + launcher for the current user.
# Run ONCE on the Linux desktop machine:  ./install-desktop.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APPS="$HOME/.local/share/applications"
ICONS="$HOME/.local/share/icons/hicolor"
DESKTOP_DIR="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
mkdir -p "$APPS"

# --- remove the pre-rename installation ----------------------------------
# The product was "Anora Ops" until 2026-07-27. Writing the new entries does
# NOT retire the old ones: they are separate files under separate names, so
# without this the operator ends up with two launchers, one of them pointing
# at scripts that were renamed out from under it.
for old in anora-ops anora-ops-terminal; do
  rm -f "$APPS/$old.desktop" "$DESKTOP_DIR/$old.desktop"
done
for s in 32 48 64 128 256 512; do
  rm -f "$ICONS/${s}x${s}/apps/anora-ops.png"
done

# icons into the hicolor theme, every size
for s in 32 48 64 128 256 512; do
  d="$ICONS/${s}x${s}/apps"
  mkdir -p "$d"
  cp "$HERE/icons/huginn-$s.png" "$d/huginn.png"
done

# The Icon= line below uses this ABSOLUTE path rather than the theme name
# "huginn". Theme lookup depends on an icon cache that only rebuilds when
# gtk-update-icon-cache succeeds -- and it refuses to run at all when
# hicolor/ has no index.theme, which a user-local theme dir usually lacks.
# That failure was swallowed by `2>/dev/null || true`, so the launcher
# appeared with no artwork and nothing said why. An absolute path is read
# straight off disk and cannot miss.
ICON_PATH="$ICONS/512x512/apps/huginn.png"

# The GUI is the main entry: console.html served by Huginn on
# 127.0.0.1:8790. The terminal console remains as a second entry for
# when a browser is the wrong tool.
# Terminal=false, deliberately: Terminal=true crashed BEFORE any window
# appeared on a desktop with no registered terminal handler for
# .desktop files. The GUI launcher needs no terminal -- it backgrounds
# a server and opens a browser, and reports problems via notify-send.
cat > "$APPS/huginn.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Huginn
Comment=IT ops console -- triage, threat, backup verification
Exec=$HERE/gui-launch.sh
Icon=$ICON_PATH
Terminal=false
Categories=System;Monitor;
DESK
chmod +x "$APPS/huginn.desktop"

# The verb menu genuinely needs a terminal, so one is launched
# explicitly -- whichever exists -- instead of trusting Terminal=true.
TERM_CMD=""
for t in gnome-terminal konsole xfce4-terminal x-terminal-emulator xterm; do
  command -v "$t" >/dev/null 2>&1 && { TERM_CMD="$t"; break; }
done
if [ -n "$TERM_CMD" ]; then
  case "$TERM_CMD" in
    gnome-terminal) EXEC_LINE="$TERM_CMD -- $HERE/ops-console.sh" ;;
    *)              EXEC_LINE="$TERM_CMD -e $HERE/ops-console.sh" ;;
  esac
  cat > "$APPS/huginn-terminal.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Huginn (terminal)
Comment=Verb menu in a terminal -- no server needed
Exec=$EXEC_LINE
Icon=$ICON_PATH
Terminal=false
Categories=System;Monitor;
DESK
  chmod +x "$APPS/huginn-terminal.desktop"
else
  echo "  note: no terminal emulator found; skipping the terminal entry."
fi

# desktop icon too, if a Desktop folder exists
if [ -d "$DESKTOP_DIR" ]; then
  cp "$APPS/huginn.desktop" "$DESKTOP_DIR/"
  chmod +x "$DESKTOP_DIR/huginn.desktop"
  # GNOME marks desktop launchers untrusted until allowed; try both tools
  gio set "$DESKTOP_DIR/huginn.desktop" metadata::trusted true 2>/dev/null || true
fi

update-desktop-database "$APPS" 2>/dev/null || true
# hicolor needs an index.theme before its cache will build at all.
# Borrow the system one rather than let the refresh fail quietly.
if [ ! -f "$ICONS/index.theme" ] && [ -f /usr/share/icons/hicolor/index.theme ]; then
  cp /usr/share/icons/hicolor/index.theme "$ICONS/index.theme"
fi
if [ -f "$ICONS/index.theme" ]; then
  gtk-update-icon-cache -f -t "$ICONS" >/dev/null 2>&1 \
    || echo "  note: icon cache not rebuilt; Icon= uses an absolute path, so this is cosmetic."
fi

echo "  installed. Find 'Huginn' in your app menu and on the Desktop."
echo "  If the desktop icon says untrusted: right-click -> Allow Launching."
