"""Fork-boundary tests (A1) — the platform stays standalone, the fork reaches
it through exactly one door.

The vendored Anora fork is ~2.6× the platform's own code, and every scar in
the journal — the two-`skills`-package collision above all — is fork-gravity
leaking across a boundary that was a convention, not a check. These make the
boundary a failing test.

**Rule A — the platform's runtime never imports the fork.** `contracts`,
`platform_support`, `engines`, `domains`, `agents`, `skills` and `storage`
must import no fork module (`anora_core` / `anora_services` / `anora`). If
they did, the platform could no longer run or be tested without the 51k-line
fork, and "runnable standalone" — the whole reason it is a separate project —
would quietly rot. `tools/` is exempt on purpose: the integration test, the
memory benchmark and the verify harnesses exist to cross the boundary and
measure it.

**Rule B — the fork stays gone.** It was archived 2026-07-26 once answering
(its last role) was removed. There is no bridge to police any more, so the
rule is the stronger one: `ai/` must not reappear.

Rule A is now also proven empirically, everywhere: the platform runs with no
fork present at all.

Run: python3 tools/test_fork_boundary.py
"""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FORK_MODULES = {"anora_core", "anora_services", "anora"}
PLATFORM_RUNTIME = ("contracts", "platform_support", "engines", "domains",
                    "agents", "skills", "storage")
_SKIP_PARTS = {"__pycache__", ".venv", "venv", "node_modules"}

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _top_level_imports(path: Path):
    """The set of top-level module names a file imports."""
    names = set()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return names
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:      # absolute import only
                names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
    return names


def _py_files(root: Path):
    for path in root.rglob("*.py"):
        if _SKIP_PARTS & set(path.parts):
            continue
        yield path


def test_platform_runtime_never_imports_the_fork():
    """Rule A: the runtime layers stay fork-free (tools/ exempt)."""
    violations = []
    for layer in PLATFORM_RUNTIME:
        layer_dir = ROOT / layer
        if not layer_dir.exists():
            continue
        for path in _py_files(layer_dir):
            bad = _top_level_imports(path) & FORK_MODULES
            if bad:
                violations.append(f"{path.relative_to(ROOT)}: imports {sorted(bad)}")
    check(not violations, (
        "platform runtime imports the fork — keep the layers standalone and "
        "put integration code in tools/:\n  " + "\n  ".join(violations)))


def test_platform_runtime_layers_are_actually_present():
    """A guard against the guard: if a layer dir vanished, Rule A above would
    pass by scanning nothing. Assert the layers exist so the check has teeth."""
    missing = [l for l in PLATFORM_RUNTIME if not (ROOT / l).is_dir()]
    check(not missing, f"expected runtime layers missing: {missing}")


def test_the_fork_is_gone_and_stays_gone():
    """Rule B (post-archival): there is no vendored fork, and none comes back.

    The fork was archived to ../attic/anora-fork-20260726 on 2026-07-26, once
    answering — its last remaining role — was removed. Rule B used to police
    the one bridge that was allowed to import the platform; with no fork there
    is no bridge, so the rule becomes the stronger one: **`ai/` must not
    reappear.** Re-vendoring a 51k-line assistant is exactly the drift this
    theme existed to stop, and it should fail a test, not be noticed later.
    """
    fork = ROOT / "ai"
    check(not fork.exists(), (
        "ai/ is back — the vendored fork was archived deliberately "
        "(../attic/anora-fork-20260726). If it must return, that is a decision "
        "to record in LONG-TERM.md, not a directory to add quietly."))


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
