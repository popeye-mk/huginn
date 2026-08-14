"""Write a directory into an ISO 9660 image with a Joliet tree.

Called by `build_iso.sh`. Uses `pycdlib` so no root, no loop mount and no
`xorriso` are needed — this has to build in environments where installing
system packages is not an option.

**Joliet is what Windows reads.** Without it, filenames come back as
`VERIFY.CMD;1` and the disc looks broken to the person it was made for.
Rock Ridge is added too so the same image mounts sensibly on Linux.

The directory is deliberately flat — one zip, one script, one batch file,
one readme. ISO 9660 limits directory depth to 8 levels, which
Diagnostic Companion's source tree exceeds on its own; the flat layout
sidesteps that entirely rather than relying on a relaxation flag.
"""

import sys
from pathlib import Path

import os

import pycdlib

# Carries the build id so the mounted drive in Explorer names the build.
# ISO 9660 allows 32 characters, A-Z 0-9 and underscore.
VOLUME_ID = os.environ.get("HUGINN_VOLUME_ID", "HUGINN_VERIFY")[:32]


def _iso_name(name: str) -> str:
    """ISO 9660 8.3 name. Joliet carries the readable one."""
    stem, _, suffix = name.rpartition(".")
    stem = (stem or name)[:8].upper()
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in stem)
    return f"/{safe}.{suffix[:3].upper()};1" if suffix else f"/{safe};1"


def build(source: Path, output: Path) -> None:
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident=VOLUME_ID)

    for path in sorted(source.iterdir()):
        if not path.is_file():
            raise SystemExit(f"the ISO layout must stay flat; found {path}")
        data = path.read_bytes()
        iso.add_fp(
            _open(data), len(data),
            _iso_name(path.name),
            rr_name=path.name,
            joliet_path=f"/{path.name}",
        )
        print(f"    + {path.name}  ({len(data):,} bytes)")

    iso.write(str(output))
    iso.close()


def _open(data: bytes):
    import io
    return io.BytesIO(data)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: write_iso.py <source-dir> <output.iso>")
    build(Path(sys.argv[1]), Path(sys.argv[2]))
