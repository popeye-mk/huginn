"""Download threat feeds to disk. The only part of R8 that uses the network.

    python3 tools/update_feeds.py

**Separate from everything else on purpose.** The platform reads feeds
from disk and never fetches during a diagnostic run, because the network
is exactly what is broken when this tool is most needed — a threat check
that requires working DNS to report DNS poisoning is a check that fails
when it counts.

**The auth key is never an argument.** It is read from
`HUGINN_ABUSECH_KEY` or `data/secrets/abusech.key`, which is gitignored.
A key on a command line ends up in shell history, in `ps` output, and in
any log that records the command — the same reasoning that keeps the
restic password in a file rather than a flag.

Licence: abuse.ch data is **CC0** — usable commercially and
non-commercially without restriction. That is why these feeds were
chosen over UT1, whose ShareAlike terms would infect any merged
derivative and collide with an open-core model.
"""

import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FEED_DIR = ROOT / "data" / "feeds"
KEY_FILE = ROOT / "data" / "secrets" / "abusech.key"

# `recent.csv` rather than `full.csv.zip`: the recent export covers the
# last days at a few hundred KB, while the full export is a large zip
# whose extra history is mostly expired IOCs. Coverage that arrives in
# two seconds gets refreshed; coverage that takes a minute does not.
FEEDS = {
    "threatfox": (
        "https://threatfox-api.abuse.ch/v2/files/exports/{key}/recent.csv",
        True,   # needs auth key
    ),
    "feodotracker": (
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        False,  # no key, but frequently empty after law-enforcement takedowns
    ),
}

TIMEOUT = 60


def auth_key() -> str:
    """Read the key from the environment or the gitignored file."""
    from_env = os.environ.get("HUGINN_ABUSECH_KEY", "").strip()
    if from_env:
        return from_env
    try:
        return KEY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def fetch(name: str, url: str, key: str) -> bool:
    """Download one feed. Reports rather than raises."""
    target = FEED_DIR / f"{name}.csv"
    try:
        request = urllib.request.Request(
            url.format(key=key), headers={"User-Agent": "huginn/0.1"}
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        print(f"  FAIL  {name}: HTTP {exc.code}"
              f"{' — check the auth key' if exc.code in (401, 403) else ''}")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
        return False

    FEED_DIR.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")

    rows = [ln for ln in body.splitlines() if ln and not ln.startswith("#")]
    # An empty feed is downloaded successfully and is still useless.
    # Saying so here is cheaper than discovering it during an incident.
    note = "  — EMPTY, matching against it proves nothing" if not rows else ""
    print(f"  ok    {name}: {len(rows):,} rows -> {target.name}{note}")
    return True


def main() -> int:
    key = auth_key()
    print("\n  Updating threat feeds")
    print("  " + "-" * 60)
    if not key:
        print(f"  no auth key ({KEY_FILE} or HUGINN_ABUSECH_KEY)")
        print("  free key: https://auth.abuse.ch/ — key-free feeds still run")
        print()

    failures = 0
    for name, (url, needs_key) in FEEDS.items():
        if needs_key and not key:
            print(f"  skip  {name}: needs an auth key — NOT verified, just skipped")
            failures += 1
            continue
        if not fetch(name, url, key):
            failures += 1

    print("  " + "-" * 60)
    print(f"  {len(FEEDS) - failures}/{len(FEEDS)} feeds updated\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
