"""Prepare an inbox for batch learning: rename, dedupe, quarantine.

    python3 tools/inbox_prep.py <folder>

The filename becomes the document's citation and its forget-handle, so
names matter — but nobody renames 139 files by hand. Rules, applied in
place with a full accounting and nothing deleted:

- **junk stripped from names**: "(1)", "[Autosaved]", "edited version",
  doubled spaces, trailing spaces before the extension
- **exact duplicates** (same content hash) move to `_skipped/dups/` —
  the first copy stays and is learned once
- **executables and other unlearnable types** move to `_skipped/other/`
  — an .exe in a knowledge inbox is at best clutter and at worst a
  student's submission with their name on it
- files that would collide after cleaning keep a ` ~2` suffix rather
  than overwriting anything
"""

import hashlib
import re
import shutil
import sys
from pathlib import Path

LEARNABLE = (".txt", ".md", ".docx", ".pptx", ".pdf")

_NOISE_BITS = (
    re.compile(r"\s*\(\d+\)\s*$"),          # (1) copies
    re.compile(r"\s*\[[^\]]*\]\s*", re.I),   # [Autosaved] etc.
    re.compile(r"\s*edited version.*$", re.I),
    re.compile(r"\s+$"),
)


def clean_stem(stem: str) -> str:
    for pattern in _NOISE_BITS:
        stem = pattern.sub("", stem)
    return re.sub(r"\s{2,}", " ", stem).strip() or "unnamed"


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def prep(folder: Path) -> int:
    dups = folder / "_skipped" / "dups"
    other = folder / "_skipped" / "other"
    seen: dict = {}
    renamed = deduped = quarantined = kept = 0

    for path in sorted(p for p in folder.iterdir() if p.is_file()):
        if path.suffix.lower() not in LEARNABLE:
            other.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), other / path.name)
            print(f"  quarantine  {path.name}")
            quarantined += 1
            continue

        digest = _hash(path)
        if digest in seen:
            dups.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), dups / path.name)
            print(f"  duplicate   {path.name}  (same content as "
                  f"{seen[digest]})")
            deduped += 1
            continue

        stem = clean_stem(path.stem)
        target = path.with_name(stem + path.suffix.lower())
        if target != path:
            n = 2
            while target.exists() and target != path:
                target = path.with_name(f"{stem} ~{n}{path.suffix.lower()}")
                n += 1
            path.rename(target)
            print(f"  renamed     {path.name} -> {target.name}")
            renamed += 1
        seen[digest] = target.name
        kept += 1

    print(f"\n  kept {kept}  renamed {renamed}  duplicates {deduped}  "
          f"quarantined {quarantined}")
    print(f"  quarantined files are in {folder / '_skipped'} — review and")
    print("  delete them yourself; this tool moves, never destroys.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_dir():
        raise SystemExit(__doc__)
    sys.exit(prep(Path(sys.argv[1]).resolve()))
