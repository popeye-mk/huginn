"""Locating bundled data files, frozen or not (spec §20).

The knowledge base, chains, triage profiles, policies and error codes
are data files, not code. Every loader found them with
`os.path.dirname(__file__)`, which is correct when running from source
and wrong the moment the tool is packaged.

PyInstaller's one-file mode unpacks the bundle into a temporary
directory at startup and points `sys._MEIPASS` at it. `__file__` for a
frozen module refers to a path inside the archive, so
`dirname(__file__)/pattern_kb/entries.yaml` does not exist — the tool
starts, then fails to load its own knowledge base. That failure is
especially bad here: an empty rule set produces *no findings*, which
renders as a clean bill of health. A packaging mistake would look
exactly like a healthy machine.

`resource_path()` resolves both cases. `assert_data_files_present()`
turns a missing-data bug into a loud startup error instead of a
confidently empty report — the same "absence is never health"
principle (§3.4) applied to the tool's own installation.
"""

import os
import sys

# Data directories that must ship with the binary. Listed explicitly so
# the packaging spec and the startup check cannot drift apart: both
# import this list rather than each maintaining their own copy.
# `tests/fixtures` is included deliberately. `diag demo` is a shipped
# feature (§14.5) and it replays those exact snapshots — the same ones
# the test suite asserts against, so the demo can never show a finding
# the tests do not also cover. That property is only worth having if the
# fixtures actually ship with the binary.
DATA_DIRS = ("pattern_kb", "policy", os.path.join("tests", "fixtures"))

REQUIRED_DATA_FILES = (
    os.path.join("pattern_kb", "entries.yaml"),
    os.path.join("pattern_kb", "chains.yaml"),
    os.path.join("pattern_kb", "triage.yaml"),
    os.path.join("pattern_kb", "error_codes.yaml"),
    os.path.join("policy", "kmo-default.yaml"),
    os.path.join("tests", "fixtures", "dying_disk.json"),
    os.path.join("tests", "fixtures", "healthy.json"),
)


def is_frozen():
    """True when running from a PyInstaller (or similar) bundle."""
    return getattr(sys, "frozen", False)


def base_path():
    """Directory that bundled data files live under.

    Frozen: PyInstaller's extraction directory. Source: this file's
    directory, which is the repository root.
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return meipass
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(*parts):
    """Absolute path to a bundled data file."""
    return os.path.join(base_path(), *parts)


def missing_data_files():
    """Required data files that are not where they should be."""
    return [rel for rel in REQUIRED_DATA_FILES if not os.path.isfile(resource_path(rel))]


def assert_data_files_present():
    """Fail loudly at startup if the knowledge base did not ship.

    Without this, a packaging mistake produces an empty rule set, and an
    empty rule set produces no findings — which reads as "this machine
    is healthy". Refusing to start is the only honest response to not
    knowing what you know (§3.4).
    """
    missing = missing_data_files()
    if not missing:
        return

    where = "inside the packaged binary" if is_frozen() else f"under {base_path()}"
    raise SystemExit(
        "Diagnostic Companion cannot start: required data files are missing "
        f"{where}:\n"
        + "\n".join(f"  - {rel}" for rel in missing)
        + "\n\nThis is a packaging fault, not a problem with the machine being "
          "diagnosed. Running without a knowledge base would report every "
          "machine as healthy, so the tool refuses to start instead."
    )
