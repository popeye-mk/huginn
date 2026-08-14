"""Restic engine wrapper.

Restic is the only backup tool supported in v1. That is a deliberate
narrowing: supporting three tools badly proves nothing about recovery,
and every one of them has a different snapshot model, so the abstraction
would have to be invented before any of it had been used once.

**Restic answers three questions and this wrapper exposes exactly those:**

- `snapshots` — what is claimed to exist
- `check` — is the repository internally consistent
- `restore` — can the data actually come back out

Only the third is evidence. The first two are necessary and nowhere near
sufficient: a repository can pass `check` and still restore a machine
that will not boot, which is precisely the gap between the 92% who
believe they have backups and the 69% who recover.

**Credentials are never taken as arguments.** The repository password
comes from the environment (`RESTIC_PASSWORD`, `RESTIC_PASSWORD_FILE`)
or a file path handed to restic, so it does not end up in a command
list that this platform logs, stores in `EngineOutput.command`, and
later renders in a console.
"""

import os
from pathlib import Path
from typing import Dict, List, Optional

from contracts.errors import EngineNotFoundError
from engines.base import EngineOutput, run_command
from platform_support import resolve_binary

NAME = "restic"

# Restore of a full system image is slow and must not be killed halfway:
# a partial restore looks exactly like a corrupt backup, and the whole
# point of this module is not to make false negative claims.
RESTORE_TIMEOUT = 3600
CHECK_TIMEOUT = 900
LIST_TIMEOUT = 120


class ResticEngine:
    """Wrapper over the restic binary."""

    name = NAME

    def __init__(
        self,
        repository: str = "",
        password_file: Optional[Path] = None,
        binary_dir: Optional[Path] = None,
    ):
        self.repository = repository or os.environ.get("RESTIC_REPOSITORY", "")
        self.password_file = Path(password_file) if password_file else None
        self.binary_dir = Path(binary_dir) if binary_dir else None

    # -- availability ----------------------------------------------------

    def _binary(self) -> Path:
        dirs = (self.binary_dir,) if self.binary_dir else ()
        return resolve_binary(NAME, search_dirs=dirs)

    def is_available(self) -> bool:
        try:
            self._binary()
            return True
        except Exception:  # noqa: BLE001
            return False

    def is_configured(self) -> bool:
        """Whether a repository is known.

        Separate from `is_available` because the two produce different
        advice: "restic is not installed" and "restic is installed but
        this platform was never told which repository to verify" are
        different problems with different fixes.
        """
        return bool(self.repository)

    # -- verbs -----------------------------------------------------------

    def snapshots(self, host: str = "", timeout: int = LIST_TIMEOUT) -> EngineOutput:
        """List snapshots the repository claims to hold."""
        command = self._base_command() + ["snapshots", "--json"]
        if host:
            command += ["--host", host]
        return run_command(
            engine=NAME,
            command=command,
            timeout=timeout,
            parse_json=True,
            env=self._env(),
        )

    def check(self, read_data_percent: int = 0, timeout: int = CHECK_TIMEOUT) -> EngineOutput:
        """Repository integrity.

        `read_data_percent` samples actual pack files rather than only
        metadata. Default 0 because a full read of a large repository can
        take hours; the caller chooses how much evidence it wants and the
        result records what was sampled, so a metadata-only check is
        never later reported as a data check.
        """
        command = self._base_command() + ["check"]
        if read_data_percent:
            command += ["--read-data-subset", f"{read_data_percent}%"]
        return run_command(
            engine=NAME,
            command=command,
            timeout=timeout,
            parse_json=False,
            env=self._env(),
        )

    def restore(
        self,
        snapshot_id: str,
        target: Path,
        include: Optional[List[str]] = None,
        timeout: int = RESTORE_TIMEOUT,
    ) -> EngineOutput:
        """Restore a snapshot into `target`.

        `target` is always supplied by the caller and never defaults to
        anything on the live system. A restore verification that could
        write over the machine it is verifying would be a data-loss tool
        wearing a data-safety label.
        """
        target = Path(target)
        if not target.is_absolute():
            raise EngineNotFoundError(
                NAME, "restore target must be an absolute path",
                detail=str(target),
            )

        command = self._base_command() + [
            "restore", snapshot_id, "--target", str(target),
        ]
        for pattern in include or []:
            command += ["--include", pattern]

        return run_command(
            engine=NAME,
            command=command,
            timeout=timeout,
            parse_json=False,
            env=self._env(),
        )

    # -- internals -------------------------------------------------------

    def _base_command(self) -> List[str]:
        if not self.repository:
            raise EngineNotFoundError(
                NAME, "no restic repository configured",
                detail="set RESTIC_REPOSITORY or pass repository=",
            )
        command = [str(self._binary()), "--repo", self.repository]
        if self.password_file:
            command += ["--password-file", str(self.password_file)]
        return command

    def _env(self) -> Dict[str, str]:
        """Process environment for restic.

        Inherited rather than constructed, so credentials the admin
        already exported keep working without this platform reading,
        copying or persisting them.
        """
        env = dict(os.environ)
        env.setdefault("RESTIC_PROGRESS_FPS", "0")
        return env
