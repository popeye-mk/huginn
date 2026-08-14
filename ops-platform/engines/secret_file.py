"""Lock a just-written secret file down to its owner.

Thin, and best-effort by contract. The caller has already written the file
with `0o600`; on POSIX that IS the restriction and this engine does nothing.
On Windows `0o600` only toggles the read-only attribute and leaves the ACL
inherited from the parent folder, so the SMTP password could be readable by
anyone the folder granted. `platform_support.restrict_file_command` returns
the `icacls` invocation that strips inheritance and grants the current user
alone; this runs it.

**UNVERIFIED on Windows.** It is written from the documented `icacls`
behaviour and has not been run against a real Windows ACL from this
codebase, the same standing this project gives the Hyper-V console reader.
It therefore NEVER raises: a lockdown that failed must not stop the secret
being saved, because a saved-but-less-restricted credential is strictly
better than a credential the operator believes was saved and was not. The
return value says whether it ran, so a caller — or a test — can tell the
difference rather than assume success.
"""

import subprocess
from typing import Optional

from platform_support.commands import restrict_file_command

NAME = "secret_file"


def restrict_to_owner(path: str, run=None) -> Optional[bool]:
    """Best-effort owner-only lockdown. Returns:

    - None  — nothing to do on this OS (POSIX: chmod already did it).
    - True  — the platform command ran and reported success.
    - False — the command was needed, ran, and did NOT succeed.

    Never raises. `run` is injectable so a test can exercise every branch
    without a real `icacls` on the machine running the suite.
    """
    command = restrict_file_command(path)
    if command is None:
        return None                            # POSIX: 0o600 is the guarantee
    runner = run or _run
    try:
        return bool(runner(command))
    except Exception:                          # noqa: BLE001 - never fatal
        return False


def _run(command) -> bool:
    """Run the lockdown command; True on a clean exit."""
    result = subprocess.run(command, capture_output=True, text=True,
                            timeout=20, check=False)
    return result.returncode == 0
