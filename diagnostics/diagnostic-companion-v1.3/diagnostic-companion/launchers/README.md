# Launchers

Everything to do with running the tool by clicking rather than typing.
Kept together because these files are only meaningful as a set, and
scattered across the project they were hard to find and easy to
mismatch.

```
launchers/
  linux/
    install-desktop-entry.sh   installs the applications-menu entry and desktop icon
    diag-window                opens a terminal and runs the menu (see below)
    run-diagnostic.sh          launcher for a USB stick
  windows/
    Install-Shortcut.ps1       creates Desktop and Start Menu shortcuts
    INSTALL-SHORTCUT.bat       double-click wrapper for the above
    RUN-DIAGNOSTIC.bat         launcher for a USB stick
  icons/
    diag-icon.svg / .png       Linux desktop entries
    diag-icon.ico              Windows shortcuts, and embedded in diag.exe
  README-FOR-USB.txt           ships on the stick as README.txt
```

Use the entry points at the project root rather than these directly:

```bash
./install-launcher.sh      # Linux
install-launcher.bat       # Windows
```

## Why there are separate wrapper scripts

**`diag-window` (Linux).** `Terminal=true` in a `.desktop` file is no
longer dependable: GNOME dropped its built-in handling in favour of the
`xdg-terminal-exec` specification, and many distributions ship no
provider for it. A console program then launches with no terminal
attached, the menu has nowhere to draw, and the launcher appears to do
nothing at all. `diag-window` opens a terminal explicitly, and the
generated `.desktop` sets `Terminal=false`.

**`INSTALL-SHORTCUT.bat` (Windows).** Double-clicking a `.ps1` opens it
in Notepad, and the default execution policy blocks local scripts. The
batch wrapper bypasses the policy for that one invocation only.

## Why the icons are generated, not hand-drawn

`tools/make_icons.py` draws them with Pillow. Rasterising the SVG would
need cairosvg, rsvg-convert or Inkscape — a heavy dependency for an
icon — and more importantly, sizes below 32px get *simpler geometry*
rather than a downscaled 256px image, which is unreadable mush at 16px.

## Two bugs these files exist to avoid

Both were found on real machines, and both fail silently:

- **The desktop folder is not `~/Desktop`.** It is localised, and on
  Windows with OneDrive Backup it is redirected entirely. Both
  installers ask the system where it is.
- **Files copied from this repository are mode 0600.** An icon the
  desktop shell cannot read renders as a blank page with no error
  anywhere, indistinguishable from a wrong path. Both installers chmod
  explicitly.
