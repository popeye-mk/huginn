"""Shared constants + file helpers for the architecture rules.

Extracted from `test_architecture.py` (Theme C) so the rules file carries the
*rules*, not the scaffolding — and so neither file drifts toward the 400-line
hard limit the rules themselves enforce (the test file was two lines from it).
No logic here decides pass/fail; it only names the limits and walks the tree.
"""

import ast
import os
import sys
from pathlib import Path

def _platform_root() -> Path:
    """The directory that IS the platform — found by structure, not position.

    `Path(__file__).parent.parent` was the obvious way and it broke on the
    b024 disc: on Windows it resolved to the *extraction root*, so the rules
    scanned Diagnostic Companion and netdiag as well. `_layer_of` then saw
    `ops-platform` as the first path part instead of `engines`, nothing was
    recognised as a layer, and four rules mis-fired at once — reporting
    `engines/base.py` as "subprocess outside engines/".

    Anchoring on structure instead: walk up from this file until we find the
    directory that actually holds the layers. That is true wherever the tree
    is unpacked, on any OS, however `__file__` resolves.
    """
    here = Path(__file__).resolve()
    for candidate in [here.parent.parent, *here.parents]:
        if (candidate / "contracts").is_dir() and (candidate / "engines").is_dir():
            return candidate
    return here.parent.parent          # last resort; the guard test catches it


ROOT = _platform_root()
sys.path.insert(0, str(ROOT))

# Rule: module length. 300 soft (warn), 400 hard (fail).
SOFT_LINE_LIMIT = 300
HARD_LINE_LIMIT = 400
FUNCTION_LINE_LIMIT = 50

# Rule: dependency direction. Index = layer depth; a layer may import
# only from layers at the same depth or lower.
LAYER_ORDER = {
    "contracts": 0,
    "platform_support": 0,   # OS facts are as foundational as data shapes
    "engines": 1,
    "domains": 2,
    "agents": 3,
    "skills": 4,
    "storage": 1,
    "console": 4,
    # The native assistant shell (A3) — hosts the skills and routes to the
    # domains, so it sits above everything. It loads skills dynamically, never
    # by static import, so it takes on no upward edge.
    "runtime": 5,
}

BANNED_MODULE_NAMES = {"utils.py", "helpers.py", "misc.py", "common.py"}

# Maintenance/orchestration tools legitimately shell out — to git, to the
# test scripts, to the benchmark — the same reason `packaging/` is skip-listed.
# They are CI harnesses, not the layered application code the rule governs.
_SUBPROCESS_ALLOWED = {"tools/codebase_health.py"}

# `ai/` holds a vendored snapshot of Anora — another project's source.
# Our layering and size rules describe how *this* codebase is built and
# do not govern code we did not write. Excluding it is not a pass: the
# fork's own large modules are recorded in PROGRESS.md rather than
# silently skipped, and anything the platform authors inside the fork is
# covered by its own tests.
# `packaging/` is excluded for a different reason than `ai/`: it is not
# application code at all. It runs on a machine where the platform is not
# installed yet, before any layer of it exists there, and it must shell
# out to a Python interpreter it just located. Making it conform to the
# layer model would mean pretending a bootstrap script is a domain
# service. Its own correctness is checked by running it, on Windows,
# which is the only place it does anything.
# `diagnostics/` and `network/` are OTHER PROJECTS (Diagnostic Companion,
# netdiag). They sit beside the platform in the repo and INSIDE the payload on
# the verification disc. They were never ours to govern — the b024 disc made
# that visible by scanning them when ROOT resolved one level too high.
SKIP_DIRS = {
    ".git", "__pycache__", ".venv", "fixtures", "schema", "ai", "packaging",
    "diagnostics", "network", "attic",
}

_FILE_CACHE = None


def python_files():
    # Scanned once and cached. Seven tests call this, and on a slow
    # mount each full rglob costs ~6 seconds — the suite timed out at
    # 45s doing the identical walk seven times. The tree does not
    # change mid-run; scanning it repeatedly verified nothing extra.
    global _FILE_CACHE
    if _FILE_CACHE is None:
        _FILE_CACHE = [
            path for path in ROOT.rglob("*.py")
            if not any(part in SKIP_DIRS for part in path.parts)
        ]
    return _FILE_CACHE


def ps1_files():
    """PowerShell scripts, with pruned descent.

    os.walk rather than rglob: rglob visits every file under .venv
    (tens of thousands) just so a filter can discard them. Pruning the
    directory list stops the descent entirely.
    """
    skip = {".git", ".venv", "node_modules", "__pycache__"}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for f in filenames:
            if f.endswith(".ps1"):
                yield Path(dirpath) / f


def non_ascii_windows_scripts():
    """`.bat`/`.cmd` files carrying non-ASCII bytes, as (path, bad-bytes).

    Same cp1252 hazard as `.ps1`: the console decodes a batch file in the
    OEM/ANSI codepage, so a typographic dash or arrow prints as mojibake or,
    inside a quoted string, ends it early. These are double-clicked by the
    operator, so a wrong byte is seen first by them — the worst place to
    find it. The scan lives here so the test stays a one-liner.
    """
    skip = {".git", ".venv", "node_modules", "__pycache__"}
    offenders = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for f in filenames:
            if f.endswith((".bat", ".cmd")):
                path = Path(dirpath) / f
                bad = sorted({b for b in path.read_bytes() if b > 127})
                if bad:
                    offenders.append((path.relative_to(ROOT),
                                      [hex(b) for b in bad][:8]))
    return offenders


def layer_of(path: Path):
    try:
        top = path.relative_to(ROOT).parts[0]
    except ValueError:
        return None
    return top if top in LAYER_ORDER else None


def imports_of(tree):
    """Top-level package name of every import in a module."""
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names += [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.append(node.module.split(".")[0])
    return names


def domain_of(path: Path):
    parts = path.relative_to(ROOT).parts
    if len(parts) >= 2 and parts[0] == "domains":
        return parts[1]
    return None


# --- disc + isolation scaffolding -----------------------------------------
#
# Parsing lives here so test_architecture.py carries the rules and not the
# string-handling. Both feed rules that exist because the same mistake was
# made twice: work that is counted but never actually run.

import re  # noqa: E402  (kept beside the helpers that use it)

VERIFIER = ROOT / "packaging" / "verify_windows.py"

#: Importing any of these reaches `dispatch`, which claims the data
#: directory for whichever machine runs it.
DISPATCH_MODULES = ("runtime.router", "runtime.app", "runtime.server")


def disc_suites():
    """(listed, omitted) from the verification disc's runner, or (None, None).

    `None` means there is no disc tooling in this tree — the rule then has
    nothing to say, rather than something wrong to say.
    """
    if not VERIFIER.is_file():
        return None, None
    source = VERIFIER.read_text(encoding="utf-8")
    body, _, tail = source.partition("DELIBERATELY_OMITTED")
    listed = set(re.findall(r'"(tools/test_\w+\.py)"', body))
    omitted = set(re.findall(r'"(tools/test_\w+\.py)"', tail))
    return listed, omitted


def test_suites():
    """Every suite in tools/, as the disc would name it."""
    return {f"tools/{p.name}" for p in ROOT.glob("tools/test_*.py")}


def suites_that_reach_dispatch_unguarded():
    """Suites that would claim the real data directory when run."""
    offenders = []
    for path in sorted(ROOT.glob("tools/test_*.py")):
        source = path.read_text(encoding="utf-8")
        if not any(mod in source for mod in DISPATCH_MODULES):
            continue
        if "HUGINN_OWNER_FILE" in source:
            continue
        offenders.append(path.name)
    return offenders
