"""Retro-scrub — apply the privacy rules to memory that predates them.

    python3 tools/scrub_memory.py

learn.py scrubs on the way in, but 81 documents entered before the
door existed and carry e-mail addresses and scrub-list names (a
teacher's name and LinkedIn URL surfaced the moment verification
looked). This applies the same scrub() to every existing entry, with
the same safety: backup to ../attic/ first, benchmark gate after.
"""

import datetime
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from learn import MEMORY, ATTIC, scrub  # noqa: E402


def main() -> int:
    memory = json.loads(MEMORY.read_text(encoding="utf-8"))
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = ATTIC / f"memory-pre-scrub-{stamp}.json"
    ATTIC.mkdir(parents=True, exist_ok=True)
    shutil.copy2(MEMORY, backup)

    total = touched = 0
    for key, value in memory.items():
        clean, count = scrub(str(value))
        if count:
            memory[key] = clean
            total += count
            touched += 1

    MEMORY.write_text(json.dumps(memory, indent=1, ensure_ascii=False),
                      encoding="utf-8")
    print(f"\n  redactions           {total} across {touched} chunk(s)")
    print(f"  backup               {backup.name}")
    print("  Now run the gate:  python3 tools/memory_benchmark.py --engine keyword")
    return 0


if __name__ == "__main__":
    sys.exit(main())
