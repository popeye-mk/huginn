"""OS detection and binary resolution — the only module that branches on
operating system.

Everywhere else in the codebase treats the platform as already resolved.
That is the rule that keeps "runs on Windows and Linux" from decaying
into "runs on whichever one was last tested": OS knowledge scattered
across twenty files is twenty places to forget.

netdiag ships a separate binary per platform
(`netdiag_linux_amd64`, `netdiag_windows_amd64.exe`), so the mapping
lives here rather than in the engine that calls it.
"""

import os
import platform
import shutil
from pathlib import Path
from typing import Optional

from contracts.errors import EngineNotFoundError

WINDOWS = "windows"
LINUX = "linux"
MACOS = "darwin"


def current_os() -> str:
    """Normalised OS name: 'windows', 'linux' or 'darwin'."""
    return platform.system().lower()


def is_windows() -> bool:
    return current_os() == WINDOWS


def is_linux() -> bool:
    return current_os() == LINUX


# Per-tool, per-OS binary names. Adding a tool means adding a row here,
# not an `if platform.system()` somewhere in a domain.
BINARY_NAMES = {
    "netdiag": {
        LINUX: "netdiag_linux_amd64",
        WINDOWS: "netdiag_windows_amd64.exe",
        MACOS: "netdiag_darwin_amd64",
    },
    "restic": {
        LINUX: "restic",
        WINDOWS: "restic.exe",
        MACOS: "restic",
    },
}


def binary_name(tool: str) -> str:
    """The filename this tool has on the current OS."""
    try:
        per_os = BINARY_NAMES[tool]
    except KeyError:
        raise EngineNotFoundError(
            tool, f"no binary mapping registered for {tool!r}"
        ) from None

    name = per_os.get(current_os())
    if name is None:
        raise EngineNotFoundError(
            tool,
            f"{tool} has no known binary for {current_os()}",
            detail=f"known: {', '.join(sorted(per_os))}",
        )
    return name


def resolve_binary(tool: str, search_dirs=()) -> Path:
    """Locate a tool's executable for the current OS.

    Looks in explicit directories first, then an env override
    (`OPS_<TOOL>_PATH`), then PATH. Raises rather than returning None so
    a missing tool fails at the call site with a message naming what is
    missing and where we looked.
    """
    name = binary_name(tool)

    override = os.environ.get(f"OPS_{tool.upper()}_PATH")
    if override:
        candidate = Path(override)
        if candidate.is_file():
            return candidate
        raise EngineNotFoundError(
            tool, f"OPS_{tool.upper()}_PATH points at a missing file",
            detail=str(candidate),
        )

    for directory in search_dirs:
        candidate = Path(directory) / name
        if candidate.is_file():
            return candidate

    found = shutil.which(name)
    if found:
        return Path(found)

    searched = ", ".join(str(d) for d in search_dirs) or "(none)"
    raise EngineNotFoundError(
        tool,
        f"could not find {name}",
        detail=f"searched dirs: {searched}; and PATH",
    )


def os_label() -> str:
    """Human-readable OS identity, e.g. 'Linux 6.8.0' or 'Windows 11'.

    Exists so reporting code has somewhere to get this without calling
    `platform.system()` directly — otherwise every log line and report
    header becomes an exception to the one-place-knows-the-OS rule, and
    the rule stops meaning anything.
    """
    return f"{platform.system()} {platform.release()}".strip()


def hostname() -> str:
    """This machine's name, as the platform identifies it.

    One place resolves it so that every subsystem uses the same string.
    A backup verification filed under `web-02` and a device row under
    `web-02.internal` are two machines as far as the database is
    concerned, and the fleet view would show a phantom.

    A known limitation, recorded rather than hidden: hostname is not a
    stable identity. Rename or reimage a machine and its history splits.
    A durable identifier needs a machine UUID, which none of the current
    engines report.
    """
    import socket
    return socket.gethostname()


def python_executable() -> str:
    """Interpreter to use when running Python-based engines.

    `sys.executable` rather than a hardcoded "python3", which does not
    exist on a default Windows install.
    """
    import sys
    return sys.executable
