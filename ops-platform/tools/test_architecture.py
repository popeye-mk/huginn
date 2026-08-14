"""Architecture enforcement — the rules in ARCHITECTURE.md, made executable.

A written rule decays; a failing test does not. Every check here maps to
a rule in ARCHITECTURE.md, and each exists because breaking it produces a
specific mess:

- god-files → modules nobody can change safely
- upward imports → the layer model inverted, everything coupled
- cross-domain imports → subdomains that cannot be worked on independently
- subprocess outside engines → domains that need real tools to test
- OS branching outside platform_support → "works on the OS I tested"
- unreferenced modules → abandoned work becoming archaeology

Run: python3 tools/test_architecture.py
"""

import ast
import sys
from pathlib import Path

# Constants + tree-walk helpers live in arch_rules so this file carries the
# rules, not the scaffolding (Theme C — it was two lines from the 400 limit).
from arch_rules import (  # noqa: E402
    BANNED_MODULE_NAMES,
    FUNCTION_LINE_LIMIT,
    HARD_LINE_LIMIT,
    LAYER_ORDER,
    ROOT,
    SKIP_DIRS,
    SOFT_LINE_LIMIT,
    _SUBPROCESS_ALLOWED,
    domain_of as _domain_of,
    imports_of as _imports_of,
    layer_of as _layer_of,
    disc_suites as _disc_suites,
    non_ascii_windows_scripts as _non_ascii_windows_scripts,
    ps1_files as _ps1_files,
    python_files as _python_files,
    suites_that_reach_dispatch_unguarded as _unguarded_dispatch_suites,
    test_suites as _test_suites,
)


# --------------------------------------------------------------------------


def test_the_rules_are_pointed_at_the_platform_itself():
    """A guard against the guard: ROOT must BE the platform root.

    On the b024 disc ROOT resolved to the extraction root, so the rules
    scanned Diagnostic Companion and netdiag too. `_layer_of` then returned
    None for everything (the first path part was `ops-platform`, not a layer),
    and four rules mis-fired at once — `engines/base.py` was reported as
    "subprocess outside engines/". Every rule below silently depends on ROOT
    being right, so ROOT being right is now itself a test: it must hold the
    layers, and a known file must land in the layer it belongs to.
    """
    for layer in ("contracts", "engines", "domains", "agents", "skills"):
        assert (ROOT / layer).is_dir(), (
            f"ROOT does not look like the platform root — {layer}/ is missing "
            f"under {ROOT}. The rules would scan the wrong tree.")
    probe = ROOT / "engines" / "base.py"
    if probe.is_file():
        assert _layer_of(probe) == "engines", (
            f"engines/base.py resolved to layer {_layer_of(probe)!r} — ROOT is "
            f"wrong and every layer rule will mis-fire.")


def test_no_god_files():
    """No module past the hard line limit."""
    violations = []
    warnings = []
    for path in _python_files():
        lines = len(path.read_text(encoding="utf-8").splitlines())
        rel = path.relative_to(ROOT)
        if lines > HARD_LINE_LIMIT:
            violations.append(f"{rel}: {lines} lines (hard limit {HARD_LINE_LIMIT})")
        elif lines > SOFT_LINE_LIMIT:
            warnings.append(f"{rel}: {lines} lines (soft limit {SOFT_LINE_LIMIT})")

    for w in warnings:
        print(f"      note: approaching limit — {w}")
    assert not violations, "God-files found:\n  " + "\n  ".join(violations)


def test_no_overlong_functions():
    violations = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = (node.end_lineno or node.lineno) - node.lineno
                if length > FUNCTION_LINE_LIMIT:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{node.lineno} "
                        f"{node.name}() is {length} lines"
                    )
    assert not violations, "Overlong functions:\n  " + "\n  ".join(violations)


def test_no_catchall_module_names():
    """No utils.py / helpers.py / misc.py — they collect unrelated code."""
    violations = [
        str(p.relative_to(ROOT))
        for p in _python_files()
        if p.name in BANNED_MODULE_NAMES
    ]
    assert not violations, (
        "Catch-all module names found (name modules for what they do):\n  "
        + "\n  ".join(violations)
    )


def test_dependencies_point_downward():
    """A layer may not import from a layer above it."""
    violations = []
    for path in _python_files():
        layer = _layer_of(path)
        if layer is None:
            continue
        depth = LAYER_ORDER[layer]
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for imported in _imports_of(tree):
            if imported in LAYER_ORDER and LAYER_ORDER[imported] > depth:
                violations.append(
                    f"{path.relative_to(ROOT)} ({layer}) imports {imported}"
                )
    assert not violations, (
        "Upward imports break the layer model:\n  " + "\n  ".join(violations)
    )


def test_domains_do_not_import_each_other():
    """Subdomains stay independent; the agent layer coordinates them."""
    violations = []
    for path in _python_files():
        own = _domain_of(path)
        if own is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                parts = node.module.split(".")
                if parts[0] == "domains" and len(parts) > 1 and parts[1] != own:
                    violations.append(
                        f"{path.relative_to(ROOT)} imports domains.{parts[1]}"
                    )
    assert not violations, (
        "Cross-domain imports:\n  " + "\n  ".join(violations)
    )


def test_subprocess_only_in_engines():
    """Every subprocess call lives in engines/, so domains stay testable."""
    violations = []
    for path in _python_files():
        if _layer_of(path) == "engines":
            continue
        if path.relative_to(ROOT).as_posix() in _SUBPROCESS_ALLOWED:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if "subprocess" in _imports_of(tree):
            violations.append(str(path.relative_to(ROOT)))
    assert not violations, (
        "subprocess outside engines/ (wrap the tool in an engine instead):\n  "
        + "\n  ".join(violations)
    )


def test_os_branching_only_in_platform_support():
    """OS knowledge stays in one module, or cross-platform support decays."""
    violations = []
    for path in _python_files():
        if _layer_of(path) == "platform_support":
            continue
        # This module names the markers in order to detect them; excluding
        # it prevents the rule from flagging its own definition.
        if path.name == Path(__file__).name:
            continue
        source = path.read_text(encoding="utf-8")
        for marker in ("platform.system()", "sys.platform", "os.name =="):
            if marker in source:
                violations.append(f"{path.relative_to(ROOT)}: {marker}")
    assert not violations, (
        "OS branching outside platform_support/:\n  " + "\n  ".join(violations)
    )


def test_no_unreferenced_modules():
    """Catch abandoned work before it becomes archaeology."""
    modules, referenced = {}, set()
    for path in _python_files():
        if path.name in ("__init__.py",) or path.name.startswith("test_"):
            continue
        if _layer_of(path) in ("engines", "domains", "agents"):
            modules[path.stem] = path.relative_to(ROOT)

    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module:
                    referenced.update(node.module.split("."))
                # `from domains.diagnostics import mapping` binds the
                # module as an alias name, not as part of node.module —
                # missing these reports imported modules as orphans.
                referenced.update(a.name for a in node.names)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    referenced.update(alias.name.split("."))

    orphans = [str(rel) for stem, rel in modules.items() if stem not in referenced]
    assert not orphans, (
        "Modules nothing imports (delete or wire up):\n  " + "\n  ".join(orphans)
    )


def test_contracts_import_nothing_internal():
    """Contracts are the foundation; they depend on no other layer."""
    violations = []
    internal = set(LAYER_ORDER) - {"contracts"}
    for path in (ROOT / "contracts").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for imported in _imports_of(tree):
            if imported in internal:
                violations.append(
                    f"{path.relative_to(ROOT)} imports {imported}"
                )
    assert not violations, (
        "contracts/ must not import other layers:\n  " + "\n  ".join(violations)
    )


def test_empty_domain_directories_are_reported():
    """Empty subdomain folders are untidy, not fatal — report them."""
    empties = [
        str(d.relative_to(ROOT))
        for d in (ROOT / "domains").iterdir()
        if d.is_dir() and d.name not in SKIP_DIRS and not any(d.rglob("*.py"))
    ]
    for e in empties:
        print(f"      note: empty domain dir (build or delete): {e}")


def test_powershell_files_survive_windows_powershell_5():
    """PowerShell 5.1 reads a BOM-less file as Windows-1252, not UTF-8.

    Found the hard way. An em-dash inside a double-quoted string is three
    UTF-8 bytes; decoded as Windows-1252 they become `a<euro>"` -- and
    that trailing double-quote **terminates the string early**, turning
    the rest of the file into parse errors that point everywhere except
    the actual cause.

    Windows PowerShell 5.1 is still the default on Windows 11, so this
    is not a legacy concern. PowerShell 7 reads UTF-8 correctly and
    would have hidden the bug.

    Either fix alone is sufficient; both are cheap. ASCII content cannot
    be mis-decoded, and a BOM removes the guess entirely.
    """
    offenders = []
    # This test deliberately does NOT use SKIP_DIRS: that list exists to
    # keep the *architecture* rules off the Anora fork, but encoding is
    # not an architecture opinion -- Setup-Anora.ps1 sat in ai/ with 237
    # non-ASCII characters and no BOM, one Windows run away from the
    # same parse-error wall the harness hit. Users run these scripts.
    for path in sorted(_ps1_files()):
        raw = path.read_bytes()
        if raw[:3] == b"\xef\xbb\xbf":
            continue  # BOM present: encoding is unambiguous
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            offenders.append(f"{path.relative_to(ROOT)}: not valid UTF-8")
            continue
        bad = sorted({c for c in text if ord(c) > 127})
        if bad:
            offenders.append(
                f"{path.relative_to(ROOT)}: no BOM and non-ASCII "
                f"{''.join(bad)[:20]!r} -- will mis-parse under PowerShell 5.1"
            )

    assert not offenders, (
        "PowerShell scripts that Windows will mis-read:\n  "
        + "\n  ".join(offenders)
    )


def test_platform_skills_never_import_the_skills_package():
    """A platform skill file must never `from skills…`/`import skills…`.

    The fork ships its OWN `skills` package. When the platform is loaded
    inside the fork, `skills` resolves THERE, so a cross-skill import like
    `from skills.patrol import run_patrol` raises `ModuleNotFoundError: No
    module named 'skills.patrol'` and takes the whole platform down — every
    verb, triage included. Shared code between skills lives under `agents/`
    (unique to this codebase, collision-proof), the same home as
    `recalling.py`. This makes that standing decision a failing test instead
    of a lesson to relearn — it cost a live outage on 2026-07-23.
    """
    violations = []
    for path in _python_files():
        if _layer_of(path) != "skills":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "skills":
                violations.append(f"{path.relative_to(ROOT)}: from {node.module} import …")
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] == "skills":
                        violations.append(f"{path.relative_to(ROOT)}: import {a.name}")
    assert not violations, (
        "platform skill imports the `skills` package (move shared code to "
        "agents/ — the fork's own `skills` shadows it and the load fails):\n  "
        + "\n  ".join(violations)
    )


def test_every_suite_runs_all_of_its_tests():
    """The `if __name__ == "__main__"` runner must be the LAST thing in a suite.

    Every test file here collects its tests by walking `globals()` from
    inside that block. Anything defined AFTER it does not exist yet when the
    loop runs, so it is silently never executed — and the suite prints
    "N tests passed" and exits 0, having skipped them.

    That is not hypothetical: three tests appended to test_timeline.py on
    2026-07-27 never ran once, while the battery reported 34/34 green. A
    test that cannot fail is worse than no test, because it is counted.
    """
    offenders = []
    for path in ROOT.glob("tools/test_*.py"):
        source = path.read_text(encoding="utf-8")
        marker = source.rfind('if __name__ == "__main__":')
        if marker == -1:
            continue                                  # not a self-running suite
        after = source[marker:]
        # Any top-level def/class after the runner is unreachable by it.
        stray = [line.split("(")[0].strip()
                 for line in after.splitlines()
                 if line.startswith(("def ", "class "))]
        if stray:
            offenders.append(f"{path.name}: {', '.join(stray)} defined after the runner")
    assert not offenders, (
        "tests defined after the __main__ runner never execute:\n  "
        + "\n  ".join(offenders))


def test_windows_batch_files_are_plain_ascii():
    """`.bat`/`.cmd` cp1252 mojibake is seen first by the operator. See .ps1."""
    bad = _non_ascii_windows_scripts()
    assert not bad, "Windows batch files must be plain ASCII: " + str(bad)


def test_no_suite_can_claim_the_real_data_directory():
    """A test that dispatches must redirect `HUGINN_OWNER_FILE` first.

    `dispatch` claims an unclaimed `data/` for the machine running it —
    right in production, wrong in a test, where it locks the operator out on
    the next verb. It happened; three suites needed the fix, found one at a
    time. This makes the fourth impossible to forget.
    """
    offenders = _unguarded_dispatch_suites()
    assert not offenders, (
        "these suites reach dispatch and would claim the real data/ directory "
        "— set HUGINN_OWNER_FILE to a temp path before importing:\n  "
        + "\n  ".join(offenders))


def test_the_disc_runs_every_suite():
    """The verification disc's suite list must not drift behind the repo.

    A suite added here and not to `packaging/verify_windows.py` is never run
    on Windows, while the report still prints "N/N passed" and is filed as
    proof — counted but never run, on the artifact whose whole job is to BE
    evidence. It has happened twice. Omissions are fine; undeclared ones are
    not.
    """
    listed, omitted = _disc_suites()
    if listed is None:
        return                                  # no disc tooling in this tree
    missing = sorted(_test_suites() - listed - omitted)
    assert not missing, (
        "suites the verification disc would never run (add to SUITES, or to "
        "DELIBERATELY_OMITTED with a reason):\n  " + "\n  ".join(missing))


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  ok    {name}")
            except AssertionError as exc:
                print(f"  FAIL  {name}\n        {exc}")
                failures += 1
    print(f"\n{'PASSED' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
