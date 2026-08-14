"""Threat feeds — loaded from disk, matched, and honest about their age.

**Feeds are files. Updating them is an explicit command.** The platform
never fetches during a diagnostic run. Two reasons, and the second is
the one that matters:

1. A diagnostic that phones out on every run is a different product,
   with different privacy and firewall consequences, than one that reads
   a local file.
2. The network is exactly what is broken when this tool is most needed.
   A threat check that requires working DNS to tell you your DNS is
   being poisoned is a check that fails when it counts.

So `tools/update_feeds.py` downloads; this reads what is on disk.

## The three states a feed can be in

Learned by downloading Feodo Tracker and finding **1 entry, last updated
139 days ago** — neither missing nor empty nor healthy:

| state | meaning |
| - | - |
| absent | nobody configured a feed |
| empty | feed loaded, zero entries |
| **stale** | entries exist, but the feed stopped being updated |

The third is the dangerous one because it looks like the first two never
do: matching proceeds, finds nothing, and reports a clean result from
data that stopped being true months ago. Feed age is therefore reported
with every result, exactly as backup verification reports `data_recency`.
"""

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from contracts.indicator import Indicator

DEFAULT_FEED_DIR = Path(__file__).resolve().parent.parent / "data" / "feeds"

# Past this, the feed describes a world that has moved on. abuse.ch
# expires its own IOCs at six months for the same reason — cloud
# addresses get recycled — so a feed file older than this is reported
# as stale regardless of how many entries it holds.
STALE_AFTER_DAYS = 14


@dataclass
class FeedStatus:
    """What state a feed is in, in words a report can print."""

    name: str
    loaded: bool = False
    entry_count: int = 0
    age_days: Optional[int] = None
    reason: str = ""
    # Rows that arrived but could not be understood. Kept separate from
    # `entry_count` because "we could not read this" and "there is
    # nothing here" send an operator to different places.
    unparseable_rows: int = 0

    @property
    def is_stale(self) -> bool:
        return self.age_days is not None and self.age_days > STALE_AFTER_DAYS

    @property
    def is_usable(self) -> bool:
        return self.loaded and self.entry_count > 0

    @property
    def summary(self) -> str:
        if not self.loaded:
            return f"{self.name}: not available — {self.reason}"
        if self.unparseable_rows:
            return (
                f"{self.name}: UNREADABLE — {self.reason}. This is a parser "
                f"gap, not an empty feed"
            )
        if not self.entry_count:
            return (
                f"{self.name}: loaded but EMPTY — matching against it proves "
                f"nothing"
            )
        age = "age unknown" if self.age_days is None else f"{self.age_days}d old"
        flag = "  STALE" if self.is_stale else ""
        return f"{self.name}: {self.entry_count:,} indicators, {age}{flag}"


class ThreatFeed:
    """Indicators from one feed file, indexed for matching."""

    def __init__(self, path: Path, name: str = "", feed_dir: Optional[Path] = None):
        self.path = Path(path)
        self.name = name or self.path.stem
        self.status = FeedStatus(name=self.name)
        self._by_address: Dict[str, List[Indicator]] = {}
        self._by_domain: Dict[str, Indicator] = {}
        self._load()

    # -- loading ---------------------------------------------------------

    def _load(self) -> None:
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            self.status.reason = f"no feed file at {self.path}"
            return
        except OSError as exc:
            self.status.reason = f"feed unreadable: {exc}"
            return

        self.status.loaded = True
        self.status.age_days = _feed_age_days(text, self.path)

        rows = [ln for ln in text.splitlines() if ln.strip()
                and not ln.startswith("#")]
        parser = _pick_parser(rows)
        if parser is None and rows:
            # Rows arrived and none could be understood. That is NOT an
            # empty feed, and saying so matters: the first live run
            # downloaded Feodo Tracker into a ThreatFox-only parser and
            # reported "EMPTY", which was accidentally true and would
            # have stayed silent if the feed had held 2,000 entries.
            self.status.reason = (
                f"{len(rows)} row(s) present but in an unrecognised format"
            )
            self.status.unparseable_rows = len(rows)
            return

        for indicator in (parser(rows, self.name) if parser else []):
            self._index(indicator)
        self.status.entry_count = len(self._by_domain) + sum(
            len(v) for v in self._by_address.values()
        )

    def _index(self, indicator: Indicator) -> None:
        if not indicator.is_matchable:
            return
        if indicator.ioc_type == "domain":
            self._by_domain[indicator.value.lower()] = indicator
        else:
            self._by_address.setdefault(indicator.address, []).append(indicator)

    # -- matching --------------------------------------------------------

    def match_address(self, address: str, port: Optional[int] = None):
        """Indicators for an IP, preferring an exact `ip:port` match.

        The feed publishes `157.20.182.81:425` — address *and* port —
        because that is what it observed. Matching the address alone
        throws away half the evidence and widens the false-positive
        surface to every service on a shared host, so an exact port
        match is preferred and a bare-address match is still returned
        but is visibly weaker.
        """
        candidates = self._by_address.get(address, [])
        if not candidates:
            return None
        if port is not None:
            exact = [i for i in candidates if i.port == port]
            if exact:
                return exact[0]
        return candidates[0]

    def match_domain(self, domain: str) -> Optional[Indicator]:
        return self._by_domain.get((domain or "").strip().lower().rstrip("."))

    @property
    def indicators(self) -> List[Indicator]:
        flat = list(self._by_domain.values())
        for group in self._by_address.values():
            flat.extend(group)
        return flat


def load_feeds(feed_dir: Optional[Path] = None) -> List[ThreatFeed]:
    """Every feed file present. An empty directory is a valid state."""
    directory = Path(feed_dir or DEFAULT_FEED_DIR)
    if not directory.is_dir():
        return []
    return [ThreatFeed(path) for path in sorted(directory.glob("*.csv"))]


def _pick_parser(rows: List[str]):
    """Choose a parser by looking at the data, not at the filename.

    Two feeds from the same organisation ship two formats: ThreatFox
    exports quoted CSV with fifteen columns, Feodo Tracker ships one
    bare IP per line. Naming both files `.csv` and assuming one shape
    is what produced a silently empty feed on the first live run.
    """
    if not rows:
        return None
    sample = rows[0]
    if sample.count(",") >= 9:
        return _parse_threatfox_rows
    if _looks_like_address(sample.strip()):
        return _parse_plain_addresses
    return None


def _looks_like_address(value: str) -> bool:
    parts = value.split(".")
    if len(parts) == 4:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return ":" in value and not value.startswith("#")


def _parse_plain_addresses(rows: List[str], feed_name: str) -> List[Indicator]:
    """One address per line — Feodo Tracker's blocklist format.

    These carry no confidence, no malware family and no timestamp, so
    they are recorded at the feed's own stated standard: Feodo only
    lists an address after it answers with a valid botnet C2 response,
    which is a strong claim, but the entry itself tells us nothing more.
    `certain` would overstate what a bare line supports.
    """
    indicators = []
    for row in rows:
        value = row.strip().split()[0] if row.strip() else ""
        if not _looks_like_address(value):
            continue
        indicators.append(Indicator(
            value=value,
            ioc_type="ip",
            feed=feed_name,
            threat_type="botnet_cc",
            confidence_level=75,
        ))
    return indicators


def _parse_threatfox(text: str, feed_name: str) -> List[Indicator]:
    """Parse ThreatFox CSV. Comment lines start with `#`.

    Fields arrive quoted *and* space-padded (`, "ip:port"`), so values
    are stripped. A row that cannot be understood is skipped rather than
    fatal: one malformed line must not cost the other twelve thousand.
    """
    rows = [line for line in text.splitlines() if line and not line.startswith("#")]
    return _parse_threatfox_rows(rows, feed_name)


def _parse_threatfox_rows(rows: List[str], feed_name: str) -> List[Indicator]:
    """Parse already-decommented ThreatFox rows."""
    indicators = []
    for row in csv.reader(rows, skipinitialspace=True):
        parsed = _threatfox_row(row, feed_name)
        if parsed is not None:
            indicators.append(parsed)
    return indicators


def _threatfox_row(row, feed_name: str) -> Optional[Indicator]:
    if len(row) < 10:
        return None
    try:
        return Indicator(
            value=row[2].strip(),
            ioc_type=row[3].strip(),
            feed=feed_name,
            threat_type=row[4].strip(),
            malware=row[7].strip(),
            confidence_level=int(row[9].strip() or 0),
            is_compromised=row[10].strip().lower() == "true" if len(row) > 10 else False,
            first_seen=row[0].strip(),
            last_seen=row[8].strip(),
            reporter=row[14].strip() if len(row) > 14 else "",
            tags=tuple(t for t in (row[12].strip().split(",") if len(row) > 12 else []) if t),
        )
    except (ValueError, IndexError):
        return None


def _feed_age_days(text: str, path: Path) -> Optional[int]:
    """Age from the feed's own header, falling back to the file mtime.

    The header is preferred because it states when abuse.ch generated
    the data; the file's timestamp only says when we downloaded it, and
    a fresh download of a dead feed is still a dead feed.
    """
    for line in text.splitlines()[:15]:
        if "last updated" in line.lower():
            stamp = line.split(":", 1)[-1].strip().rstrip("#").strip()
            parsed = _parse_header_time(stamp)
            if parsed is not None:
                return (datetime.now(timezone.utc) - parsed).days
    try:
        modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        return (datetime.now(timezone.utc) - modified).days
    except OSError:
        return None


def _parse_header_time(text: str) -> Optional[datetime]:
    cleaned = (text or "").replace("UTC", "").strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
