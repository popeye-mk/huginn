#!/usr/bin/env python3
"""Build the standalone binary (spec §20, §13.1).

    python3 build.py              # onefile (default, for distribution)
    python3 build.py --onedir     # fallback if AV dislikes self-extraction
    python3 build.py --check      # verify an existing build without rebuilding

Runs on the platform you are building for: PyInstaller does not
cross-compile, so a Windows .exe must be built on Windows.

The verification step at the end is the point of this script existing
rather than a one-line pyinstaller invocation. A binary that starts is
not a binary that works: the failure this project has to guard against
is the knowledge base not shipping, in which case every command still
runs and every machine is reported healthy. So the build is not
considered successful until the binary has demonstrated it can load its
own rules and produce a known finding from a known fixture.
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
IS_WINDOWS = platform.system().lower() == "windows"
EXE_NAME = "diag.exe" if IS_WINDOWS else "diag"

VERSION = "1.4.0"

VERSION_INFO_TEMPLATE = """
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({v0}, {v1}, {v2}, 0),
    prodvers=({v0}, {v1}, {v2}, 0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable('040904B0', [
        StringStruct('CompanyName', 'Diagnostic Companion'),
        StringStruct('FileDescription', 'Read-only system diagnostic tool'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', 'diag'),
        StringStruct('OriginalFilename', 'diag.exe'),
        StringStruct('ProductName', 'Diagnostic Companion'),
        StringStruct('ProductVersion', '{version}'),
      ])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def run(cmd, **kwargs):
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, check=True, **kwargs)


def ensure_pyinstaller():
    try:
        import PyInstaller  # noqa: F401
        return True
    except ImportError:
        print("PyInstaller is not installed. Install it with:")
        print("  pip install pyinstaller")
        return False


def write_version_info():
    """Windows file metadata. Not code signing — see PACKAGING.md."""
    if not IS_WINDOWS:
        return
    major, minor, patch = (VERSION.split(".") + ["0", "0"])[:3]
    path = os.path.join(ROOT, "version_info.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(VERSION_INFO_TEMPLATE.format(
            v0=int(major), v1=int(minor), v2=int(patch), version=VERSION))
    print(f"  wrote {path}")


def build(onedir=False):
    if not ensure_pyinstaller():
        return False

    print("==> Cleaning previous build")
    for d in ("build", "dist"):
        shutil.rmtree(os.path.join(ROOT, d), ignore_errors=True)

    write_version_info()

    print(f"==> Building ({'onedir' if onedir else 'onefile'})")
    if onedir:
        # --onedir cannot be expressed in the spec without editing it,
        # so this path invokes PyInstaller directly with equivalent flags.
        cmd = [
            sys.executable, "-m", "PyInstaller", "cli.py",
            "--name", "diag", "--onedir", "--console", "--noupx",
            "--clean", "--noconfirm",
        ]
        from resources import DATA_DIRS
        for d in DATA_DIRS:
            cmd += ["--add-data", f"{d}{os.pathsep}{d}"]
        for module in ("collectors.core", "collectors.optional", "collectors.windows"):
            cmd += ["--hidden-import", module]
    else:
        cmd = [sys.executable, "-m", "PyInstaller", "diag.spec",
               "--clean", "--noconfirm"]

    run(cmd, cwd=ROOT)
    return True


def binary_path(onedir=False):
    if onedir:
        return os.path.join(ROOT, "dist", "diag", EXE_NAME)
    return os.path.join(ROOT, "dist", EXE_NAME)


def verify(onedir=False):
    """Prove the binary works, not merely that it exists.

    Each check targets a way packaging can fail while still producing a
    binary that appears to run.
    """
    exe = binary_path(onedir)
    if not os.path.isfile(exe):
        print(f"FAIL: no binary at {exe}")
        return False

    size_mb = os.path.getsize(exe) / (1024 * 1024)
    print(f"\n==> Verifying {exe} ({size_mb:.1f} MB)")

    checks_passed = True

    def check(label, cmd, predicate):
        nonlocal checks_passed
        try:
            proc = subprocess.run([exe] + cmd, capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", timeout=120)
        except (subprocess.TimeoutExpired, OSError) as e:
            print(f"  FAIL  {label}: {e}")
            checks_passed = False
            return
        ok, detail = predicate(proc)
        print(f"  {'OK  ' if ok else 'FAIL'}  {label}" + ("" if ok else f" — {detail}"))
        if not ok:
            checks_passed = False

    check("starts and reports a version",
          ["--version"],
          lambda p: (VERSION in (p.stdout + p.stderr), "version string missing"))

    # The critical one: proves the knowledge base shipped. Without the
    # rules, this exits 0 and finds nothing — which is why the assertion
    # is on the finding, not on the exit code alone.
    check("knowledge base loaded (kb lint sees the rules)",
          ["kb", "lint"],
          lambda p: ("16 rules checked" in p.stdout or "rules checked" in p.stdout,
                     "kb lint did not report any rules"))

    check("a known fixture still produces its known finding",
          ["demo", "dying-disk", "--format", "json"],
          lambda p: (_demo_has_findings(p), "demo produced no findings"))

    check("decoder data shipped",
          ["decode", "0x80070005"],
          lambda p: ("Access denied" in p.stdout, "error code table missing"))

    check("policy data shipped",
          ["policy", "check", "--snapshot",
           os.path.join(ROOT, "tests", "fixtures", "healthy.json")],
          lambda p: ("Policy check" in p.stdout, "policy file missing"))

    check("a real run completes on this machine",
          ["run", "--format", "json"],
          lambda p: (_is_json(p.stdout), "run did not produce valid JSON"))

    return checks_passed


def _demo_has_findings(proc):
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return False
    return bool(payload.get("findings") or payload.get("chains"))


def _is_json(text):
    try:
        json.loads(text)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def assemble_usb_kit(onedir=False):
    """Lay out a ready-to-copy USB folder in dist/usb-kit.

    Exists so the stick is assembled the same way every time rather
    than by remembering which files to drag across.
    """
    exe = binary_path(onedir)
    if not os.path.isfile(exe):
        print("  no binary to package")
        return False

    kit = os.path.join(ROOT, "dist", "usb-kit")
    shutil.rmtree(kit, ignore_errors=True)
    os.makedirs(kit, exist_ok=True)

    shutil.copy2(exe, os.path.join(kit, os.path.basename(exe)))

    # Ship only what this platform can use. The binary is
    # platform-specific anyway — a Linux build cannot run on Windows —
    # so the other platform's files are dead weight that only invite
    # someone to try them and get a confusing error.
    launchers = os.path.join(ROOT, "launchers")
    platform_dir = os.path.join(launchers, "windows" if IS_WINDOWS else "linux")
    icon_name = "diag-icon.ico" if IS_WINDOWS else "diag-icon.png"

    sources = []
    if os.path.isdir(platform_dir):
        # install-desktop-entry.sh is for a fixed install, not a stick:
        # a desktop entry needs an absolute path and a stick's mount
        # point changes between machines.
        sources += [os.path.join(platform_dir, n)
                    for n in sorted(os.listdir(platform_dir))
                    if n != "install-desktop-entry.sh"]

    icon = os.path.join(launchers, "icons", icon_name)
    if os.path.isfile(icon):
        sources.append(icon)

    readme = os.path.join(launchers, "README-FOR-USB.txt")
    if os.path.isfile(readme):
        sources.append(readme)

    for src in sources:
        name = os.path.basename(src)
        if name == "README-FOR-USB.txt":
            name = "README.txt"
        target = os.path.join(kit, name)
        shutil.copy2(src, target)

        if name.endswith(".sh") or name == "diag-window":
            os.chmod(target, 0o755)
        else:
            # The repository may hold these as 0600; an icon the desktop
            # cannot read renders as a blank page with no error anywhere.
            os.chmod(target, 0o644)

    print(f"\n==> USB kit ready: {kit}")
    for name in sorted(os.listdir(kit)):
        size = os.path.getsize(os.path.join(kit, name))
        print(f"      {name:<28} {size:>10,} bytes")
    print("\n    Copy the contents of that folder to a USB stick.")
    return True


def main():
    parser = argparse.ArgumentParser(description="Build the diag binary")
    parser.add_argument("--onedir", action="store_true",
                        help="Build a directory instead of a single file "
                             "(fallback if AV dislikes self-extraction)")
    parser.add_argument("--check", action="store_true",
                        help="Verify an existing build without rebuilding")
    parser.add_argument("--usb", action="store_true",
                        help="Also assemble dist/usb-kit ready to copy to a stick")
    args = parser.parse_args()

    if not args.check and not build(onedir=args.onedir):
        return 1

    if not verify(onedir=args.onedir):
        print("\nBuild produced a binary, but verification FAILED. "
              "Do not distribute it.")
        return 1

    if args.usb:
        assemble_usb_kit(onedir=args.onedir)

    exe = binary_path(onedir=args.onedir)
    print(f"\nBuild verified: {exe}")
    if IS_WINDOWS:
        print("\nNext: see PACKAGING.md for what to record about Defender "
              "and SmartScreen. That result is the actual unknown here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
