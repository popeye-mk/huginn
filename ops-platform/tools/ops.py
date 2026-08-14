"""Run an ops verb from anywhere.

    python tools/ops.py triage
    python tools/ops.py census passive
    python tools/ops.py digest 30

Runs on the **native shell** — the platform's own registry and router. It used
to boot the vendored fork (and chdir into it, because the fork resolved its
data relative to the working directory); with the fork archived 2026-07-26
that indirection is gone, and this is a thin front end over `runtime`.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    from runtime.registry import SkillRegistry, auto_discover, failure_report
    from runtime.router import dispatch

    registry = SkillRegistry()
    auto_discover(registry, str(ROOT / "skills"))

    # Discovery survives a broken skill, but it must not do so quietly. A
    # verb that failed to load still has a button on the console and still
    # lives in the operator's memory; four of them were missing from this
    # shell for a day after the fork was archived, and nothing said a word.
    report = failure_report(registry)
    if report:
        print()
        print(report, file=sys.stderr)

    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        print(f"  verbs: {', '.join(registry.names())}")
        return 0

    result = dispatch(registry, " ".join(args))
    print()
    print(result.message)
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
