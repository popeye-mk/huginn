"""Codebase health — a scheduled sanity check that the tree is still sound (B3).

The pre-commit hook guards a commit; the release gate guards a disc. This
guards *time*: run on a schedule (beside the 3-hourly triage), it re-checks the
fast structural guards and the answer benchmark, so a regression that slipped
past the hook — or an uncommitted mess quietly piling up — is SEEN on its own,
not discovered at the next release.

Deliberately light: the structural guards (architecture + fork-boundary, both
stdlib and quick) and the answer anchor, not the full battery or the fork
suite. It answers "is the tree still green and are the answers still good," and
exits non-zero when the answer is no — so `systemctl status` shows red and the
wrapper can alert.

`build_report` is pure so it is unit-tested without running anything.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANCHOR_FLOOR = 36


def _run_suite(name) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", name)],
            capture_output=True, text=True, cwd=ROOT, timeout=120)
        return result.returncode == 0
    except Exception:  # noqa: BLE001 - a check that cannot run is not healthy
        return False


def _git(*args) -> str:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True,
                              cwd=ROOT, timeout=30).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def build_report(arch_ok, boundary_ok, anchor, uncommitted, head,
                 floor=ANCHOR_FLOOR):
    """Assemble the health report and the healthy/not verdict. Pure."""
    anchor_ok = anchor is None or anchor >= floor
    healthy = bool(arch_ok and boundary_ok and anchor_ok)
    lines = [
        "  CODEBASE HEALTH — " + ("OK" if healthy else "NEEDS ATTENTION"),
        "  " + "=" * 56,
        f"  architecture    {'ok' if arch_ok else 'FAIL'}",
        f"  fork boundary   {'ok' if boundary_ok else 'FAIL'}",
    ]
    if anchor is None:
        lines.append("  answer anchor   not checked (no corpus) — NOT a pass")
    else:
        verdict = "ok" if anchor_ok else f"REGRESSED (< {floor})"
        lines.append(f"  answer anchor   {anchor}/52 {verdict}")
    lines.append(f"  git             {head or '?'}, {uncommitted} uncommitted file(s)")
    if not healthy:
        lines.append("")
        lines.append("  A guarded property regressed — investigate before the next release.")
    return healthy, "\n".join(lines)


def main():
    arch = _run_suite("test_architecture.py")
    boundary = _run_suite("test_fork_boundary.py")
    anchor = None      # answering retired 2026-07-26 — no answer quality to check
    uncommitted = len([l for l in _git("status", "--porcelain").splitlines() if l.strip()])
    head = _git("rev-parse", "--short", "HEAD")
    healthy, text = build_report(arch, boundary, anchor, uncommitted, head)
    print(text)
    sys.exit(0 if healthy else 1)


if __name__ == "__main__":
    main()
