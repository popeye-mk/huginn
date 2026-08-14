#!/usr/bin/env python3
"""diag — Diagnostic Companion CLI (subset of spec §18/§20's cli.py).

Implements: run [--diff] [--format], why, baseline, simple, demo,
policy check, fix, verify, fleet, decode, kb lint.
Still future work from the spec's cli.py: watch, kb update/review, and
the Ops Console push (report --ticket) — sequenced in
Diagnostic_Companion_Next_Steps.md.
"""

import argparse
import json
import os
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from collectors.base import run_collector
from collectors.core import disk, logs, network, system
from collectors.optional import battery, smart, wifi
import console as console_mod
import menu as menu_mod
import portable as portable_mod
import resources as resources_mod
import decoder as decoder_mod
import fixes as fixes_mod
import kb_lint as kb_lint_mod
import policy as policy_mod
import triage as triage_mod
from diffing import build_diff
from redact import redact_snapshot
from interpreter import evaluate, exit_code, resolve_chains
import fleet as fleet_mod
from report import render_text
from verdict import build_verdict
from report_html import render_html
from report_simple import render_simple
from schema import SCHEMA_VERSION

# Windows equivalents exist (collectors/windows/) but are unverified —
# no Windows box in this build environment. Dispatch is wired here so
# the CLI already has the right shape for when that changes; see
# Diagnostic_Companion_Next_Steps.md.
IS_WINDOWS = platform.system().lower() == "windows"

if IS_WINDOWS:
    from collectors.windows import battery as _os_battery
    from collectors.windows import disk as _os_disk
    from collectors.windows import logs as _os_logs
    from collectors.windows import network as _os_network
    from collectors.windows import smart as _os_smart
    from collectors.windows import system as _os_system
    from collectors.windows import wifi as _os_wifi
else:
    _os_system, _os_network, _os_disk, _os_logs = system, network, disk, logs
    _os_battery, _os_wifi, _os_smart = battery, wifi, smart

# Outer (thread) timeouts. Each must exceed the collector's own
# subprocess timeout — see the note in collectors/windows/*.py. The
# network figure is the largest because that collector performs three
# DNS resolutions and two pings, any of which can be slow on a loaded
# or badly-connected machine; a real Windows VM under test load hit the
# previous 10s limit and reported the collector as timed out.
CORE_COLLECTORS = [
    ("system", _os_system.collect, 15, "unprivileged"),
    ("network", _os_network.collect, 30, "unprivileged"),
    ("disk", _os_disk.collect, 15, "unprivileged"),
    ("logs", _os_logs.collect, 25, "unprivileged"),
]

# Optional collectors (spec §4.2) auto-skip when not applicable (no
# battery, no Wi-Fi adapter) or not privileged (disk health needs
# root/Administrator). Both OS implementations report the same field
# names so one KB rule covers both — see collectors/windows/smart.py
# for where the underlying sensor genuinely differs.
OPTIONAL_COLLECTORS = [
    ("battery", _os_battery.collect, 20, "unprivileged"),
    ("wifi", _os_wifi.collect, 20, "unprivileged"),
    ("smart", _os_smart.collect, 40, "elevated"),
]

# Baseline storage location (spec §6.1). A per-user file is enough for
# a v1 single-machine tool; the Ops Console's per-asset timeline (§18)
# is the real fleet-scale version of this, and is v2 work.
BASELINE_PATH = Path.home() / ".diagnostic-companion" / "baseline.json"


def _active_collectors():
    return CORE_COLLECTORS + OPTIONAL_COLLECTORS


def build_snapshot():
    sections = {}
    for name, func, timeout_s, privilege_level in _active_collectors():
        sections[name] = run_collector(name, func, timeout_s=timeout_s, privilege_level=privilege_level)

    return {
        "schema_version": SCHEMA_VERSION,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "os": platform.system().lower(),
        "sections": sections,
    }


def _write_output(content, args, default_suffix=".txt"):
    """Write to --output if given, else to stdout.

    --output exists because shell redirection is not encoding-safe. On
    Windows, `diag run --format html > report.html` writes through the
    console's codepage, so any character the codepage cannot represent
    either mangles or raises — producing a corrupt or truncated file
    that still looks like it was created successfully. Writing the file
    directly in UTF-8 sidesteps the console entirely.
    """
    target = getattr(args, "output", None)
    if not target:
        console_mod.write(content)
        return

    path = Path(target)
    if path.is_dir():
        path = path / f"diagnostic-report{default_suffix}"
    path.write_text(content, encoding="utf-8")
    # Progress goes to stderr so stdout stays clean for piping.
    print(f"Written: {path.resolve()}", file=sys.stderr)


def _emit(snapshot, args, diff=None, extra_not_checked=None, profile=None):
    # Findings are always computed from the RAW snapshot — redaction is
    # a display/export concern (spec §4.3), never allowed to change what
    # gets diagnosed. --anon only affects what's shown/exported below.
    findings, worth_checking, not_checked = evaluate(snapshot)

    # Collectors a triage profile deliberately skipped are merged into
    # "Not checked" — narrowing the run must never read as health (§3.4).
    if extra_not_checked:
        not_checked = list(not_checked) + list(extra_not_checked)

    chains, remaining_findings = resolve_chains(findings)

    # Triage weighting is display-only: same findings, different order.
    # `findings` (used for the exit code) is deliberately left untouched.
    if profile:
        remaining_findings = triage_mod.prioritise(remaining_findings, profile)

    display_snapshot = redact_snapshot(snapshot) if getattr(args, "anon", False) else snapshot

    # Scanned from the RAW snapshot: redaction may rewrite log text, and
    # a decoded code is a fact about the machine, not about the export.
    decoded_codes = decoder_mod.scan_snapshot(snapshot)
    verdict = build_verdict(findings, not_checked, chains)
    score = fleet_mod.health_score(snapshot)

    if args.format == "html":
        html = render_html(display_snapshot, remaining_findings, worth_checking,
                           not_checked, chains=chains, diff=diff,
                           decoded_codes=decoded_codes, verdict=verdict, score=score)
        _write_output(html, args, default_suffix=".html")
    elif args.format == "json":
        _write_output(json.dumps(
            {
                "anonymized": bool(getattr(args, "anon", False)),
                "snapshot": display_snapshot,
                "findings": findings,
                "chains": chains,
                "worth_checking": worth_checking,
                "verdict": verdict,
                "health_score": score,
                "decoded_codes": decoded_codes,
                "diff": diff,
            },
            indent=2,
        ), args, default_suffix=".json")
    else:
        text = render_text(display_snapshot, remaining_findings, worth_checking,
                           not_checked, chains=chains, diff=diff,
                           decoded_codes=decoded_codes, verdict=verdict, score=score)
        _write_output(text, args, default_suffix=".txt")

    # exit_code is always computed from the flat, pre-chain `findings` —
    # the chain narrative must never soften what automation reacts to (§16).
    return exit_code(findings)


def cmd_run(args):
    snapshot = build_snapshot()

    diff = None
    if args.diff:
        if not BASELINE_PATH.exists():
            print(f"No baseline found at {BASELINE_PATH} — run `diag baseline` first.", file=sys.stderr)
            return 1
        baseline_snapshot = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        baseline_findings, _, _ = evaluate(baseline_snapshot)
        current_findings, _, _ = evaluate(snapshot)
        diff = build_diff(baseline_snapshot, snapshot, baseline_findings, current_findings)

    return _emit(snapshot, args, diff=diff)


def cmd_baseline(args):
    snapshot = build_snapshot()
    fixes_mod.stamp_snapshot(snapshot)  # §14.7 — a baseline is evidence too
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(f"Baseline saved: {BASELINE_PATH}")
    return 0


def cmd_simple(args):
    """diag simple — end-user traffic-light card (spec §14.2)."""
    snapshot = build_snapshot()
    findings, _worth_checking, not_checked = evaluate(snapshot)
    display_snapshot = redact_snapshot(snapshot) if getattr(args, "anon", False) else snapshot
    console_mod.write(render_simple(display_snapshot, findings, not_checked))
    return exit_code(findings)


DEMO_SCENARIOS = {
    "dying-disk": "dying_disk.json",
    "dns-broken": "dns_broken.json",
    "healthy": "healthy.json",
    "smart-failing": "smart_failing.json",
}


def cmd_demo(args):
    """diag demo <scenario> — spec §14.5: replay a canned snapshot
    through the real interpreter and reporter, zero setup, zero risk.
    Reuses the same fixtures the test suite proves each rule against,
    so the demo can never show a finding the tests don't also cover.
    """
    if args.scenario not in DEMO_SCENARIOS:
        options = ", ".join(sorted(DEMO_SCENARIOS))
        print(f"Unknown scenario '{args.scenario}'. Options: {options}", file=sys.stderr)
        return 1

    fixture_path = resources_mod.resource_path(
        "tests", "fixtures", DEMO_SCENARIOS[args.scenario]
    )
    with open(fixture_path, encoding="utf-8") as f:
        snapshot = json.load(f)

    # Banner goes to stderr, not stdout: --format json must be pure,
    # parseable JSON on stdout regardless of which command produced it.
    print(
        f"[demo: {args.scenario}] replaying a canned snapshot — nothing was collected from this machine\n",
        file=sys.stderr,
    )
    return _emit(snapshot, args)


def cmd_why(args):
    """diag why <symptom> — complaint-driven triage (spec §7)."""
    profile = triage_mod.get_profile(args.symptom)
    if profile is None:
        # Unknown symptom falls back to a full run rather than erroring —
        # same graceful-degradation principle as an unmatched log line (§7).
        print(
            f"Unknown symptom '{args.symptom}' — running a full diagnostic instead.\n"
            f"Known symptoms: {', '.join(triage_mod.known_symptoms())}",
            file=sys.stderr,
        )
        args.diff = False
        return cmd_run(args)

    available = _active_collectors()
    selected = triage_mod.select_collectors(profile, available)
    excluded = triage_mod.excluded_collectors(profile, available)

    print(
        f"[why {args.symptom}] {profile['description']} — running "
        f"{len(selected)} of {len(available)} collectors",
        file=sys.stderr,
    )

    sections = {}
    for name, func, timeout_s, privilege_level in selected:
        sections[name] = run_collector(name, func, timeout_s=timeout_s, privilege_level=privilege_level)

    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "os": platform.system().lower(),
        "sections": sections,
    }

    extra = [(cid, "not_run", f"not relevant to symptom '{args.symptom}'") for cid in excluded]
    return _emit(snapshot, args, extra_not_checked=extra, profile=profile)


def cmd_policy(args):
    """diag policy check — declarative compliance (spec §9)."""
    if args.snapshot:
        snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    else:
        snapshot = build_snapshot()

    policy_path = args.policy or policy_mod.DEFAULT_POLICY
    results = policy_mod.check(snapshot, policy_mod.load_policy(policy_path))

    if args.format == "json":
        print(json.dumps({
            "policy": os.path.basename(policy_path),
            "summary": policy_mod.summarise(results),
            "results": results,
        }, indent=2))
    else:
        console_mod.write(policy_mod.render_policy(results, os.path.basename(policy_path)))

    return policy_mod.policy_exit_code(results)


def cmd_fix(args):
    """diag fix — dry-run by default, always (spec §14.3)."""
    if args.snapshot:
        snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    else:
        snapshot = build_snapshot()

    findings, _worth, _not_checked = evaluate(snapshot)
    plan = fixes_mod.plan_fixes(findings, snapshot.get("os", platform.system().lower()))

    console_mod.write(fixes_mod.render_plan(plan, snapshot.get("os", "linux")))

    if args.apply:
        # Deliberately not implemented as a silent no-op: executing
        # remediation needs per-fix confirmation, a post-fix collector
        # re-run to prove the change worked, and a rollback story for
        # anything non-reversible. Half of that is worse than none.
        print(
            "\n--apply is not enabled in this build. The dry-run above is the "
            "complete plan; run the commands manually if you agree with them.",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_verify(args):
    """diag verify <snapshot.json> — tamper-evident check (spec §14.7)."""
    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    ok, actual, expected = fixes_mod.verify_snapshot(snapshot, args.sha256)

    if ok is None:
        print(f"No integrity hash recorded in this snapshot.\nsha256: {actual}")
        print("Pass --sha256 <hash> to check against a hash recorded elsewhere "
              "(e.g. in the ticket).", file=sys.stderr)
        return 1
    if ok:
        print(f"VERIFIED — snapshot matches its recorded hash.\nsha256: {actual}")
        return 0
    print(f"MISMATCH — this snapshot does not match its recorded hash.\n"
          f"  expected: {expected}\n  actual:   {actual}", file=sys.stderr)
    return 2


def cmd_fleet(args):
    """diag fleet — correlation and ranked health board (spec §8, §14.6)."""
    paths = []
    for target in args.paths:
        if os.path.isdir(target):
            paths.extend(
                os.path.join(target, name)
                for name in sorted(os.listdir(target))
                if name.endswith(".json")
            )
        else:
            paths.append(target)

    snapshots = fleet_mod.load_snapshots(paths)
    if not snapshots:
        print("No readable snapshots found.", file=sys.stderr)
        return 1

    if args.format == "json":
        print(json.dumps({
            "assets": [fleet_mod.health_score(s) for s in snapshots],
            "correlations": fleet_mod.correlate(snapshots),
        }, indent=2))
    else:
        console_mod.write(fleet_mod.render_fleet(snapshots))

    # Exit 1 if any environment-level conclusion fired: a scheduled
    # fleet check should be able to signal "something is shared and
    # upstream" without parsing the report (§16).
    return 1 if any(c["environment_level"] for c in fleet_mod.correlate(snapshots)) else 0


def cmd_decode(args):
    """diag decode <code> — Windows error-code lookup (spec §10)."""
    if args.list:
        for category, code, label in decoder_mod.all_codes():
            print(f"{category:16} {code:12} {label}")
        return 0

    if not args.code:
        print("Nothing to decode. Pass a code, or --list to see them all.", file=sys.stderr)
        return 1

    result = decoder_mod.decode(args.code)
    console_mod.write(decoder_mod.render_decode(args.code, result))
    # Unknown code exits 1: "I have nothing useful to say" is not success.
    return 0 if result else 1


def cmd_menu(args):
    """diag menu — the front door when the binary is double-clicked."""
    # The runner is a closure over main() so every menu option executes a
    # real command line. The menu therefore cannot drift from the
    # documented commands, and cannot grow a second diagnosis path.
    def run(argv):
        try:
            return main(argv, allow_menu=False)
        except SystemExit as e:  # main() exits; the menu must survive it
            return e.code if isinstance(e.code, int) else 0

    return menu_mod.run_menu(run)


def cmd_kb(args):
    """diag kb lint — knowledge-base discipline (spec §12.3)."""
    known = {name for name, _f, _t, _p in CORE_COLLECTORS + OPTIONAL_COLLECTORS}
    issues = kb_lint_mod.lint(known_collectors=known)
    rules = kb_lint_mod._load(kb_lint_mod.KB_PATH)
    console_mod.write(kb_lint_mod.render_lint(issues, len(rules)))
    return kb_lint_mod.lint_exit_code(issues)


VERSION = "1.4.0"

EPILOG = """
common tasks
  diag run                      check this machine now
  diag run --format html -o report.html   shareable report you can email
  diag why slow                 start from a complaint, not a full sweep
  diag menu                     guided menu, for showing someone their own machine
  diag simple                   plain-language card for a non-technical user
  diag decode 0x80070005        translate a Windows error code
  diag demo dying-disk          see what a real problem looks like, safely

before and after a change
  diag baseline                 record this machine as "known good"
  diag run --diff               show what changed since then

sharing a report safely
  diag run --anon               redact hostname, public IPs, SSID, log text

exit codes (for scripts and scheduled jobs)
  0  nothing found
  1  warnings, or checks that could not run
  2  something critical and certain

This tool only reads. It never changes anything on the machine.
"""


def main(argv=None, allow_menu=True):
    parser = argparse.ArgumentParser(
        prog="diag",
        description="Diagnostic Companion — read-only health check that explains "
                    "what it found, and says plainly what it could not check.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"diag {VERSION}")
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    run_p = sub.add_parser("run", help="Check this machine and explain what was found")
    run_p.add_argument("--format", choices=["text", "json", "html"], default="text")
    run_p.add_argument("--diff", action="store_true", help="Compare against the saved baseline")
    run_p.add_argument("-o", "--output", metavar="FILE",
                        help="Write the report to a file instead of stdout "
                             "(safer than shell redirection on Windows)")
    run_p.add_argument("--anon", action="store_true",
                        help="Redact hostname/public IPs/SSID/log free-text before output (spec §4.3, §5)")
    run_p.set_defaults(func=cmd_run)

    why_p = sub.add_parser("why", help="Diagnose from a complaint (slow, no-internet, ...)")
    why_p.add_argument("symptom", help=f"one of: {', '.join(triage_mod.known_symptoms())}")
    why_p.add_argument("--format", choices=["text", "json", "html"], default="text")
    why_p.add_argument("-o", "--output", metavar="FILE",
                        help="Write the report to a file instead of stdout "
                             "(safer than shell redirection on Windows)")
    why_p.add_argument("--anon", action="store_true", help="Redact sensitive fields before output")
    why_p.set_defaults(func=cmd_why, diff=False)

    policy_p = sub.add_parser("policy", help="Check a snapshot against a compliance policy")
    policy_p.add_argument("action", choices=["check"], nargs="?", default="check")
    policy_p.add_argument("--policy", help="Path to a policy YAML (default: policy/kmo-default.yaml)")
    policy_p.add_argument("--snapshot", help="Check a saved snapshot instead of collecting live")
    policy_p.add_argument("--format", choices=["text", "json"], default="text")
    policy_p.set_defaults(func=cmd_policy)

    fix_p = sub.add_parser("fix", help="Show whitelisted remediation for current findings (dry-run)")
    fix_p.add_argument("--apply", action="store_true", help="Execute suggested fixes (not enabled in this build)")
    fix_p.add_argument("--snapshot", help="Plan against a saved snapshot instead of collecting live")
    fix_p.set_defaults(func=cmd_fix)

    verify_p = sub.add_parser("verify", help="Prove a saved report has not been altered")
    verify_p.add_argument("snapshot", help="Path to a snapshot JSON file")
    verify_p.add_argument("--sha256", help="Expected hash, if not recorded in the file itself")
    verify_p.set_defaults(func=cmd_verify)

    fleet_p = sub.add_parser("fleet", help="Correlate findings across several snapshots")
    fleet_p.add_argument("paths", nargs="+", help="Snapshot files, or a directory of them")
    fleet_p.add_argument("--correlate", action="store_true",
                         help="Accepted for spec parity; correlation always runs")
    fleet_p.add_argument("--format", choices=["text", "json"], default="text")
    fleet_p.set_defaults(func=cmd_fleet)

    decode_p = sub.add_parser("decode", help="Translate a Windows error or stop code")
    decode_p.add_argument("code", nargs="?", help="e.g. 0x80070005 or 0x7e")
    decode_p.add_argument("--list", action="store_true", help="List every known code")
    decode_p.set_defaults(func=cmd_decode)

    menu_p = sub.add_parser("menu", help="Guided menu, readable by a non-technical user")
    menu_p.set_defaults(func=cmd_menu)

    kb_p = sub.add_parser("kb", help="Knowledge-base tooling")
    kb_p.add_argument("action", choices=["lint"], nargs="?", default="lint")
    kb_p.set_defaults(func=cmd_kb)

    baseline_p = sub.add_parser("baseline", help="Save the current snapshot as the known-good baseline")
    baseline_p.set_defaults(func=cmd_baseline)

    simple_p = sub.add_parser("simple", help="Plain-language card for a non-technical user")
    simple_p.add_argument("--anon", action="store_true", help="Redact sensitive fields before output")
    simple_p.set_defaults(func=cmd_simple)

    demo_p = sub.add_parser("demo", help="Replay a realistic problem safely, no setup")
    demo_p.add_argument("scenario", choices=sorted(DEMO_SCENARIOS), nargs="?", default="dying-disk")
    demo_p.add_argument("--format", choices=["text", "json", "html"], default="text")
    demo_p.add_argument("-o", "--output", metavar="FILE",
                        help="Write the report to a file instead of stdout "
                             "(safer than shell redirection on Windows)")
    demo_p.add_argument("--anon", action="store_true", help="Redact sensitive fields before output")
    demo_p.set_defaults(func=cmd_demo)

    console_mod.configure_output()

    # Double-clicking the packaged binary from Explorer or a USB stick
    # passes no arguments. Printing usage and exiting would close the
    # window before anyone could read it, so the guided menu is the
    # right response — but only for a real console, never when piped.
    if allow_menu and menu_mod.should_auto_launch(
            argv if argv is not None else sys.argv[1:], resources_mod.is_frozen()):
        sys.exit(cmd_menu(None))

    # Refuse to run without a knowledge base. An empty rule set produces
    # no findings, which renders as "no problems found" — a packaging
    # fault would be indistinguishable from a healthy machine (§3.4).
    resources_mod.assert_data_files_present()

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # A bare `diag` used to silently run a full sweep. Showing help
        # instead is friendlier to someone meeting the tool for the
        # first time, and `diag run` is one word away.
        parser.print_help()
        sys.exit(0)

    result = args.func(args)
    if not allow_menu:
        # Called from the menu: hand the code back instead of exiting,
        # so one command's failure does not close the whole session.
        return result
    sys.exit(result)


if __name__ == "__main__":
    main()
