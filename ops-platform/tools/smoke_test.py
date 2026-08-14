"""Cross-platform smoke test — must produce the same verdict on Windows and Linux.

Run this on every machine the platform is expected to work on. It answers
one question: *does this actually work here, and if not, precisely what
is missing?*

Written to the same standard the platform holds its own tools to:
**a check that could not run is reported as SKIP, never as a pass.** A
smoke test that silently skips the netdiag engine on a machine without
netdiag would report a green run on a broken install — the exact failure
this codebase exists to prevent, committed by the tool meant to catch it.

Usage:
    python tools/smoke_test.py          # human-readable
    python tools/smoke_test.py --json   # machine-readable, for comparing OSes

Exit codes: 0 all passed (skips allowed), 1 something failed.
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS, FAIL, SKIP = "pass", "fail", "skip"

_results = []


def _record(name, status, detail=""):
    _results.append({"check": name, "status": status, "detail": detail})


def check(name, required=True):
    """Decorator: run a check, capture pass/fail/skip with its reason."""

    def wrap(fn):
        try:
            outcome = fn()
        except SkipCheck as exc:
            _record(name, SKIP, str(exc))
        except Exception as exc:  # noqa: BLE001 - a smoke test reports, never crashes
            detail = f"{type(exc).__name__}: {exc}"
            # Engine errors carry the tool's own stderr in `.detail`, and
            # that is the half worth having. The first Windows run
            # reported only "output was not valid JSON" while the actual
            # cause — ModuleNotFoundError: No module named 'yaml' — sat
            # unread in this field. A report that omits the reason has
            # wasted the trip.
            extra = getattr(exc, "detail", "")
            if extra:
                detail = f"{detail} | {_last_line(extra)}"
            _record(name, FAIL if required else SKIP, detail)
        else:
            _record(name, PASS, str(outcome or ""))
        return fn

    return wrap


class SkipCheck(Exception):
    """Raised when a check cannot run here — reported, never silently passed."""


def _last_line(text: str) -> str:
    """The end of a traceback names the fix; the start names nothing."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    return lines[-1][:180] if lines else ""


# --- environment ----------------------------------------------------------

@check("environment: python version")
def _python_version():
    from platform_support import os_label

    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 9):
        raise RuntimeError(f"Python {major}.{minor} is too old (need 3.9+)")
    return f"Python {major}.{minor} on {os_label()}"


@check("environment: platform_support resolves this OS")
def _platform_support():
    from platform_support import current_os, is_linux, is_windows

    os_name = current_os()
    if not (is_windows() or is_linux() or os_name == "darwin"):
        raise RuntimeError(f"unrecognised platform: {os_name}")
    return f"detected {os_name}"


# --- contracts ------------------------------------------------------------

@check("contracts: import and validate")
def _contracts():
    from contracts import Coverage, Finding

    f = Finding(
        id="smoke",
        source_module="manual",
        machine_id="smoke-host",
        severity="warning",
        confidence="likely",
        message="smoke test finding",
        coverage=Coverage(checked=1, total=2),
    )
    assert f.can_headline is True
    assert f.is_actionable is False
    assert str(f.coverage) == "1/2 checked"
    return "Finding + Coverage behave correctly"


@check("contracts: partial coverage is never reported as complete")
def _coverage_honesty():
    from contracts import Coverage

    partial = Coverage(checked=3, total=9)
    if partial.is_complete:
        raise RuntimeError("partial coverage reported as complete")
    try:
        Coverage(checked=10, total=9)
    except ValueError:
        return "impossible coverage rejected; partial stays partial"
    raise RuntimeError("checked > total was accepted")


# --- engines --------------------------------------------------------------

@check("engine: Diagnostic Companion available")
def _dc_available():
    from engines.diagnostic_companion import DiagnosticCompanionEngine

    engine = DiagnosticCompanionEngine()
    if not engine.is_available():
        raise SkipCheck(f"not found at {engine.cli_path}")
    return str(engine.install_path)


@check("engine: Diagnostic Companion runs (demo)")
def _dc_runs():
    from engines.diagnostic_companion import DiagnosticCompanionEngine

    engine = DiagnosticCompanionEngine()
    if not engine.is_available():
        raise SkipCheck("engine unavailable")
    ready, reason = engine.readiness()
    if not ready:
        raise RuntimeError(f"present but not runnable: {reason}")
    out = engine.run(demo="dying-disk")
    findings = (out.payload or {}).get("findings") or []
    if not findings:
        raise RuntimeError("demo scenario produced no findings")
    return f"{len(findings)} findings from demo"


@check("engine: Diagnostic Companion is actually runnable")
def _dc_ready():
    """Presence is not capability — the check that was missing.

    Three smoke-test failures on the first Windows run all traced to one
    cause: Diagnostic Companion needs PyYAML and the machine had none.
    Reporting that once, by name, is worth more than three downstream
    symptoms that each blame JSON parsing.
    """
    from engines.diagnostic_companion import DiagnosticCompanionEngine

    engine = DiagnosticCompanionEngine()
    if not engine.is_available():
        raise SkipCheck("engine not installed")
    ready, reason = engine.readiness()
    if not ready:
        raise RuntimeError(reason)
    return "cli.py runs"


@check("engine: netdiag binary resolves for this OS")
def _netdiag_available():
    from engines.netdiag import NetdiagEngine
    from platform_support import binary_name

    engine = NetdiagEngine()
    expected = binary_name("netdiag")
    if not engine.is_available():
        raise SkipCheck(f"{expected} not found in {engine.install_dir}")
    return f"resolved {expected}"


@check("engine: netdiag runs")
def _netdiag_runs():
    from engines.netdiag import NetdiagEngine

    engine = NetdiagEngine()
    if not engine.is_available():
        raise SkipCheck("engine unavailable")
    out = engine.run(timeout=90)
    payload = out.payload or {}
    if "findings" not in payload:
        raise RuntimeError(f"unexpected payload keys: {list(payload)}")
    return f"{len(payload.get('findings') or [])} findings"


# --- full stack -----------------------------------------------------------

@check("stack: diagnostics service maps findings")
def _service():
    from domains.diagnostics import DiagnosticsService

    service = DiagnosticsService()
    if not service.is_available():
        raise SkipCheck("Diagnostic Companion unavailable")
    result = service.run(demo="dying-disk")
    if not result.findings:
        raise RuntimeError("service returned no findings")
    return f"{len(result.findings)} findings, score {result.health_score.get('score')}"


@check("stack: agent routes and explains")
def _agent():
    from agents.ops_agent import OpsAgent

    agent = OpsAgent()
    if not agent.can_handle("diagnose this machine"):
        raise RuntimeError("agent failed to route a diagnose request")
    if agent.can_handle("what is the capital of France"):
        raise RuntimeError("agent claimed an unrelated request")
    if not agent.diagnostics.is_available():
        raise SkipCheck("Diagnostic Companion unavailable")
    return "routing correct"


@check("stack: skill returns text")
def _skill():
    from skills.diagnose import skill_diagnose
    from domains.diagnostics import DiagnosticsService

    if not DiagnosticsService().is_available():
        raise SkipCheck("Diagnostic Companion unavailable")

    text = skill_diagnose("")
    if not text.strip():
        raise RuntimeError("skill returned empty output")

    # **No structural threshold.** Two attempts to add one were both
    # wrong, and the way they were wrong is the lesson.
    #
    # The first Windows run reported `1 lines` where Linux reported 8.
    # That was diagnosed as a failure *from the number alone*, without
    # reading the content — and a check was written to catch it. The
    # check then failed on the real output, which turned out to be:
    #
    #   "No problems found in what could be checked — but 3 check(s)
    #    could not run. This is not a clean bill of health."
    #
    # A single, entirely correct sentence. A clean machine with partial
    # coverage produces exactly one line; a machine with findings
    # produces several. Line count measures how broken the host is, not
    # whether the skill worked.
    #
    # So this reports what it saw and lets a human judge. A smoke check
    # that invents a threshold it cannot justify is the same
    # overclaiming the platform refuses everywhere else.
    lines = [ln for ln in text.splitlines() if ln.strip()]
    return f"{len(lines)} line(s), opens {lines[0][:70]!r}"


# Security-era checks live in their own module and register themselves
# on import. Splitting by subject rather than by line count: connections
# and feeds arrived with R8 and will keep growing, while the engine and
# contract checks above have been stable since R0.
from smoke_security import register as _register_security  # noqa: E402

_register_security(check, SkipCheck)


# --- report ---------------------------------------------------------------

def _print_report():
    width = max(len(r["check"]) for r in _results) + 2
    icons = {PASS: "ok  ", FAIL: "FAIL", SKIP: "skip"}

    from platform_support import os_label

    print(f"\n  Ops Platform smoke test — {os_label()}")
    print(f"  {'-' * (width + 30)}")
    for r in _results:
        line = f"  {icons[r['status']]}  {r['check']:<{width}}"
        if r["detail"]:
            line += f"  {r['detail']}"
        print(line)

    passed = sum(1 for r in _results if r["status"] == PASS)
    failed = sum(1 for r in _results if r["status"] == FAIL)
    skipped = sum(1 for r in _results if r["status"] == SKIP)

    print(f"\n  {passed} passed, {failed} failed, {skipped} skipped")
    if skipped:
        print("  Skipped checks are NOT passes — they are things this machine "
              "could not verify.")
    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()

    if args.json:
        failed = sum(1 for r in _results if r["status"] == FAIL)
        from platform_support import current_os, os_label

        print(json.dumps(
            {
                "platform": current_os(),
                "os_label": os_label(),
                "python": ".".join(str(v) for v in sys.version_info[:3]),
                "results": _results,
            },
            indent=2,
        ))
    else:
        failed = _print_report()

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
