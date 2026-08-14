"""Finding the bootable disk inside a restored backup.

**The hole that was in the middle of R7.** `_boot_stage` took a
`disk_path` from its caller and nothing ever supplied one, so boot depth
was unreachable through the product even on a machine with a working
hypervisor. The tests passed because they called the service directly.

Fixing it required naming an assumption that had never been stated:

> Restic backs up **files**. Booting needs a **disk image**. Those are
> the same thing only when what was backed up *was* a virtual machine's
> disk.

For a file-level backup of a live server, getting to a bootable disk
means partitioning, filesystems, a bootloader and drivers — bare-metal
restore, which is a separate product and not a missing function.

So the scope is stated rather than implied: **this platform boot-tests
backups of VM disk images.** A backup with no disk image in it is not a
failure; it is a backup that cannot be boot-tested, and it says so and
stays at file depth.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

# Extensions treated as bootable disk images. `.vmdk` is included
# because backups of VMware guests are common, even though neither
# shipped sandbox can boot one — `find` reports what is there, and the
# sandbox is what refuses.
DISK_SUFFIXES = (".qcow2", ".vhdx", ".vhd", ".img", ".raw", ".vmdk", ".qed")

# Below this, the file is a placeholder, a stub or a fragment rather
# than a machine. 16 MiB is far under any real system disk and far over
# any accidental match.
MIN_IMAGE_BYTES = 16 * 1024 * 1024


@dataclass
class DiskImageSearch:
    """What was found, and why it cannot be used if it cannot."""

    path: Optional[Path] = None
    candidates: List[Path] = None
    reason: str = ""

    def __post_init__(self):
        if self.candidates is None:
            self.candidates = []

    @property
    def found(self) -> bool:
        return self.path is not None


def find_disk_image(root: Path) -> DiskImageSearch:
    """Locate exactly one bootable disk image under a restored tree.

    Ambiguity is refused rather than guessed. A backup containing three
    disk images might be one VM with three volumes, or three VMs, and
    booting whichever sorted first would produce a confident answer
    about the wrong machine.
    """
    candidates = sorted(
        path for path in Path(root).rglob("*")
        if path.is_file()
        and path.suffix.lower() in DISK_SUFFIXES
        and _size(path) >= MIN_IMAGE_BYTES
    )

    if not candidates:
        return DiskImageSearch(reason=_nothing_found_reason(root))
    if len(candidates) > 1:
        names = ", ".join(p.name for p in candidates[:4])
        return DiskImageSearch(
            candidates=candidates,
            reason=(
                f"{len(candidates)} disk images in this backup ({names}) — "
                f"which machine to boot is ambiguous, so none was chosen"
            ),
        )
    return DiskImageSearch(path=candidates[0], candidates=candidates)


def _nothing_found_reason(root: Path) -> str:
    """Say whether there were near-misses, so the answer is diagnosable.

    "No disk image found" is unhelpful when the truth is "there is one
    but it is 4 KB". Both cases are reported differently.
    """
    small = [
        path.name for path in Path(root).rglob("*")
        if path.is_file() and path.suffix.lower() in DISK_SUFFIXES
    ]
    if small:
        return (
            f"disk image(s) present but too small to be a machine "
            f"({', '.join(small[:3])}) — under {MIN_IMAGE_BYTES // (1024 * 1024)} MiB"
        )
    return (
        "this backup contains no VM disk image, so it cannot be "
        "boot-tested — file-level backups need a bare-metal restore, "
        "which this platform does not perform"
    )


def _size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0
