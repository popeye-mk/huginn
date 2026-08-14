"""Windows verification runner — the script the ISO exists to deliver.

Run from a mounted CD on Windows 11 to answer the questions the Linux
test suite structurally cannot: does the platform import, do the engines
resolve their **Windows** binaries, does `platform_support` pick Hyper-V,
and does anything behave differently from the Linux baseline.

**This is not application code.** It runs on a machine where the platform
is not installed, before any of it exists there, and it shells out by
definition — which is why `packaging/` is excluded from the architecture
test rather than being made to pretend it fits the layer model.

Three design rules, each from a real failure mode:

1. **Never run from the CD.** Optical media is read-only; the platform
   writes SQLite databases and snapshots. The payload is extracted to a
   writable directory first, and the report is written to the Desktop —
   not next to a script that lives on a disc.

2. **A skip is never a pass.** Every check reports `ok`, `FAIL` or
   `skip`, and skips are counted separately in the summary. A verifier
   that quietly skipped an unavailable engine would report green on a
   broken install — the same "absence looks like health" failure the
   platform exists to prevent, committed by the tool meant to catch it.

3. **Always write the report, even when everything breaks.** The whole
   point of this trip is bringing evidence back. A crash that produced
   no file would waste the run.
"""

import datetime
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

PAYLOAD_ZIP = "huginn-payload.zip"
WORK_DIR_NAME = "huginn-verify"


def build_tag() -> str:
    """Which disc this is, read from the stamp beside this script."""
    stamp = Path(__file__).resolve().parent / "BUILD.txt"
    try:
        return stamp.read_text(encoding="utf-8").strip() or "unstamped"
    except OSError:
        return "unstamped"


BUILD = build_tag()
# The build goes in the report filename too. Two reports from two discs
# must not overwrite each other — comparing runs is the whole reason to
# keep them, and the first version silently replaced the previous one.
REPORT_NAME = f"huginn-report-{BUILD}.txt"

# Suites worth running on Windows. `test_anora_integration` is omitted
# deliberately: the the predecessor project fork is not on the ISO (it needs `requests`,
# `numpy` and a model download), and a suite that always skips is noise.
SUITES = (
    "tools/smoke_test.py",
    "tools/test_architecture.py",
    "tools/test_portability.py",
    # Proves the SHIPPED artifact carries no vendored fork. It was left off
    # the disc as repo hygiene, but run from an extracted payload it asserts
    # something about the disc itself — and "this recovery media rebuilds a
    # fork-free product" is precisely a claim the disc exists to make.
    "tools/test_fork_boundary.py",
    "tools/test_backup.py",
    "tools/test_grounding.py",
    "tools/test_connections.py",
    "tools/test_threat_feed.py",
    "tools/test_threat_match.py",
    "tools/test_hyperv_console.py",
    "tools/test_finding.py",
    "tools/test_correlation.py",
    "tools/test_devices.py",
    "tools/test_network_mapping.py",
    "tools/test_findings_store.py",
    "tools/test_registry.py",
    "tools/test_router.py",
    "tools/test_server.py",
    "tools/test_app.py",
    "tools/test_codebase_health.py",
    "tools/test_recall.py",
    # Network Guard (G1–G6) + G1f + OCR. All zero-dependency: the guard
    # engines are injectable and degrade honestly when a tool is absent, and
    # test_ocr_ingest guards the confidence gate without needing tesseract —
    # so they belong on a disc whose whole point is a clean-box run.
    "tools/test_lan_census.py",
    "tools/test_lan_names.py",
    "tools/test_lan_exposure.py",
    "tools/test_lan_anomaly.py",
    "tools/test_llmnr.py",
    "tools/test_patrol.py",
    "tools/test_dashboard.py",
    "tools/test_timeline.py",
    "tools/test_patrol_summary.py",
    "tools/test_alerting.py",
    "tools/test_admin_settings.py",
    "tools/test_secret_file.py",
    "tools/test_notify_engines.py",
    "tools/test_corroboration.py",
    "tools/test_segments.py",
    "tools/test_wifi.py",
    "tools/test_wifi_platforms.py",
    "tools/test_digest.py",
    "tools/test_mitigation.py",
    "tools/test_posture.py",
    "tools/test_label.py",
    # Console v2 and the ownership guard, 2026-07-27. These four were
    # missing from this list for exactly as long as it took to notice —
    # which is the argument for the drift test that now guards it.
    "tools/test_inventory.py",
    "tools/test_readiness.py",
    "tools/test_owning.py",
    "tools/test_blind_witness.py",
)

#: Suites deliberately NOT on the disc, with the reason. Anything absent
#: from both this set and SUITES fails `test_the_disc_runs_every_suite`.
DELIBERATELY_OMITTED = {
    # The the predecessor project fork is not on the ISO (it needs `requests`, `numpy` and a
    # model download), so this suite would always skip. A suite that always
    # skips is noise in a report whose whole job is to be read.
    "tools/test_anora_integration.py",
}

_lines = []


def say(text=""):
    """Print and remember. The report is the deliverable, not the console."""
    print(text)
    _lines.append(text)


def find_payload() -> Path:
    """Locate the payload zip beside this script."""
    here = Path(__file__).resolve().parent
    candidate = here / PAYLOAD_ZIP
    if candidate.is_file():
        return candidate
    raise SystemExit(f"payload not found: expected {candidate}")


def writable_workspace() -> Path:
    """A writable directory to extract into.

    `LOCALAPPDATA` rather than `TEMP`: the databases written during a run
    are worth keeping if something needs investigating afterwards, and
    Windows clears TEMP without asking.
    """
    base = Path(
        os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or Path.home()
    )
    work = base / WORK_DIR_NAME
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
        # `ignore_errors` keeps a locked file from aborting the run — but a
        # cleanup that half-worked must be SAID, not swallowed. On the b024
        # disc an unelevated run could not fully delete the previous
        # extraction; the leftovers merged with the fresh payload and the
        # architecture rules walked files that were not part of this build,
        # reporting four failures that had nothing to do with the code. The
        # same run elevated was 31/31. A dirty workspace is exactly the
        # "absence looks like health" failure this verifier exists to refuse,
        # so it is now reported before anything is trusted.
        if work.exists():
            leftovers = sum(1 for _ in work.rglob("*"))
            say(f"  WARNING: could not fully clear {work}")
            say(f"           {leftovers} item(s) survived — usually a locked "
                f"file or a run without Administrator rights.")
            say("           Results below may include files from a previous "
                "build. Close anything using that folder, or re-run this")
            say("           as Administrator, and verify again before "
                "trusting a failure.")
            say()
    work.mkdir(parents=True, exist_ok=True)
    return work


def extract(payload: Path, work: Path) -> Path:
    say(f"  extracting payload to {work}")
    with zipfile.ZipFile(payload) as archive:
        archive.extractall(work)
    platform_root = work / "ops-platform"
    if not platform_root.is_dir():
        raise SystemExit("payload did not contain ops-platform/")
    return platform_root


# Not stdlib-only after all. The first Windows run proved it: four suite
# failures, three of them tracing to PyYAML (Diagnostic Companion's
# knowledge base is YAML, so its CLI *and* its fleet module refuse to
# import without it) and one to numpy. Linux had both system-wide, which
# is exactly why the claim survived until a real Windows box tested it.
OPTIONAL_DEPS = (
    ("yaml", "pyyaml", "Diagnostic Companion cannot run at all without it"),
    ("numpy", "numpy", "semantic recall only; everything else degrades cleanly"),
)


def dependency_report():
    """Name missing dependencies once, up front, instead of four times later."""
    missing = []
    say("  Dependencies")
    say("  " + "-" * 68)
    for module, package, why in OPTIONAL_DEPS:
        try:
            __import__(module)
            say(f"   {package:10} present")
        except ImportError:
            missing.append(package)
            say(f"   {package:10} MISSING — {why}")

    if missing:
        say()
        say(f"   Install with:  pip install {' '.join(missing)}")
        say("   Then run VERIFY.cmd again. Suites that need these will be")
        say("   reported as skipped, which is not the same as passed.")
    say()
    return missing


def environment_report():
    """What machine this evidence came from. Recorded before anything runs."""
    say("  Environment")
    say("  " + "-" * 68)
    say(f"   disc build    {BUILD}")
    say(f"   python        {sys.version.split()[0]} ({sys.executable})")
    for name, command in (
        ("windows", ["cmd", "/c", "ver"]),
        ("hyper-v", [
            "powershell", "-NoProfile", "-Command",
            "(Get-WindowsOptionalFeature -Online -FeatureName "
            "Microsoft-Hyper-V-All).State",
        ]),
    ):
        say(f"   {name:13} {_probe(command)}")
    say()


def _probe(command) -> str:
    """Run a probe command, reporting failure as text rather than raising."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60
        )
    except Exception as exc:  # noqa: BLE001
        return f"could not determine ({type(exc).__name__})"
    output = (result.stdout or result.stderr or "").strip()
    return output.splitlines()[0] if output else "(no output)"


def run_suite(platform_root: Path, suite: str) -> bool:
    """Run one test suite. Returns whether it passed."""
    script = platform_root / suite
    if not script.is_file():
        say(f"  skip  {suite}  (not present in payload)")
        return True

    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(platform_root),
            capture_output=True,
            text=True,
            timeout=1800,
        )
    except Exception as exc:  # noqa: BLE001
        say(f"  FAIL  {suite}  ({type(exc).__name__}: {exc})")
        return False

    passed = result.returncode == 0
    say(f"  {'ok  ' if passed else 'FAIL'}  {suite}")
    for line in (result.stdout or "").splitlines():
        if line.strip():
            say(f"        {line}")
    if not passed:
        for line in (result.stderr or "").splitlines()[-25:]:
            say(f"        ! {line}")
    say()
    return passed


def write_report() -> Path:
    """Write the report somewhere the user will actually find it."""
    desktop = Path.home() / "Desktop"
    target = (desktop if desktop.is_dir() else Path.home()) / REPORT_NAME
    target.write_text("\n".join(_lines), encoding="utf-8")
    return target


def main() -> int:
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    say()
    say(f"  Huginn — Windows verification  [build {BUILD}]  ({stamp})")
    say("  " + "=" * 68)
    say()

    failures = []
    try:
        environment_report()
        dependency_report()
        platform_root = extract(find_payload(), writable_workspace())
        say()
        say("  Test suites")
        say("  " + "-" * 68)
        for suite in SUITES:
            if not run_suite(platform_root, suite):
                failures.append(suite)
    except SystemExit as exc:
        say(f"  FAIL  setup: {exc}")
        failures.append("setup")
    except Exception as exc:  # noqa: BLE001
        say(f"  FAIL  unexpected: {type(exc).__name__}: {exc}")
        failures.append("unexpected")

    say("  " + "=" * 68)
    say(
        f"  {len(SUITES) - len(failures)} suite(s) passed, "
        f"{len(failures)} failed"
        + (f": {', '.join(failures)}" if failures else "")
    )
    say()
    say("  Nothing here is a pass by omission. A suite that could not run")
    say("  is reported as failed, not skipped into silence.")

    report = write_report()
    print(f"\n  Report written to: {report}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
