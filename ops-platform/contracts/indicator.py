"""Threat indicators — pure data.

An indicator is somebody else's claim that a value is associated with
something bad. **It is not our claim**, and the difference matters more
here than anywhere else in the platform: this is the one place where a
false positive gets an admin to block their own supplier.

Three properties of the ThreatFox data shape the design, and all three
were read off the real feed rather than assumed:

**1. The feed states its own confidence.** Every IOC carries
`confidence_level` 0–100. That is a gift — it means the platform never
has to invent a confidence for a match, and can carry the source's
uncertainty through instead of flattening it into "bad".

**2. `is_compromised` changes the remediation entirely.** A malicious
host and a *legitimate site that has been hacked* are both in the feed,
and blocking the second one blocks a real business. That distinction is
carried, not dropped.

**3. IOCs expire.** abuse.ch removes entries older than six months
because cloud IP addresses get recycled to new customers. An indicator
therefore has an age, and an old one is weaker evidence than a fresh
one — which the contract records rather than leaving to the reader.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

CONTRACT_VERSION = "0.1.0"

# What kind of thing the indicator names. Only the first two can be
# matched against anything this platform observes today; the rest are
# carried so the parser does not silently drop rows, and are excluded
# from matching by `is_matchable` rather than being deleted.
IOC_TYPES = (
    "ip:port", "ip", "domain", "url",
    "md5_hash", "sha1_hash", "sha256_hash", "email",
)

MATCHABLE_TYPES = ("ip:port", "ip", "domain")

# ThreatFox confidence_level → our vocabulary. Deliberately conservative
# at the top: the feed being 100% sure the IOC is malicious is not the
# same as us being certain *this machine* is compromised, and the
# contract must not let the two blur.
_CONFIDENCE_FLOOR_CERTAIN = 90
_CONFIDENCE_FLOOR_LIKELY = 50


@dataclass(frozen=True)
class Indicator:
    """One threat indicator, as published by a feed."""

    value: str
    ioc_type: str
    feed: str
    threat_type: str = ""          # botnet_cc, payload_delivery, ...
    malware: str = ""              # human-readable family, e.g. "Tofsee"
    confidence_level: int = 0      # 0-100, the FEED's confidence
    is_compromised: bool = False
    first_seen: str = ""
    last_seen: str = ""
    reporter: str = ""
    tags: tuple = ()
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self):
        if not self.value:
            raise ValueError("an indicator must have a value")
        if not self.feed:
            raise ValueError(
                "an indicator must name its feed — attribution is a licence "
                "condition, and an unattributed match cannot be checked"
            )

    @property
    def is_matchable(self) -> bool:
        """Whether this platform can compare it to anything it observes."""
        return self.ioc_type in MATCHABLE_TYPES

    @property
    def address(self) -> str:
        """The IP alone, for an `ip:port` indicator."""
        if self.ioc_type == "ip:port" and ":" in self.value:
            return self.value.rsplit(":", 1)[0]
        return self.value if self.ioc_type == "ip" else ""

    @property
    def port(self) -> Optional[int]:
        if self.ioc_type != "ip:port" or ":" not in self.value:
            return None
        try:
            return int(self.value.rsplit(":", 1)[1])
        except ValueError:
            return None

    @property
    def confidence(self) -> str:
        """The feed's confidence, in this platform's vocabulary.

        Carried through rather than invented. A feed that says 50 has
        told us something useful, and rounding it up to "bad" would be
        manufacturing certainty the source explicitly declined to claim.
        """
        if self.confidence_level >= _CONFIDENCE_FLOOR_CERTAIN:
            return "certain"
        if self.confidence_level >= _CONFIDENCE_FLOOR_LIKELY:
            return "likely"
        return "possible"

    @property
    def age_days(self) -> Optional[int]:
        """How old the sighting is, or None if the feed did not say."""
        seen = self.last_seen or self.first_seen
        if not seen:
            return None
        parsed = _parse_time(seen)
        if parsed is None:
            return None
        return (datetime.now(timezone.utc) - parsed).days

    @property
    def description(self) -> str:
        """One line naming what this is, for a report."""
        parts = [self.malware or self.threat_type or "unclassified threat"]
        if self.is_compromised:
            parts.append("(compromised legitimate host)")
        parts.append(f"{self.feed}, confidence {self.confidence_level}%")
        return " ".join(parts)

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_time(value: str) -> Optional[datetime]:
    """ThreatFox timestamps: `2026-07-21 05:35:20` (UTC, no zone marker)."""
    text = (value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
