"""Observed network connections — pure data.

**The input R8 did not have.** Before this, nothing in the platform
recorded what a machine *talks to*. netdiag counts sockets
(`sockets_established = 0`) and lists local listening ports; neither
engine records a single remote address. A threat feed matched against
that would have been a rule that could never fire — the same hole as
`disk_path` in the boot stage, caught this time before any matching
logic was written.

**What a connection is allowed to claim.** An observed connection is a
fact: this local socket had this remote peer at this moment. It is not
evidence of anything on its own. The word "unknown" does not appear
here, because a connection nobody recognises is not suspicious — most
of them are a browser.

Judgement belongs in the domain layer, where it can be argued with.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

CONTRACT_VERSION = "0.1.0"

# Every state that means "this machine had a peer". LISTEN is excluded
# on purpose: a listening socket has no peer, and netdiag already
# reports exposure — that is a different question from outbound reach.
#
# **The full set matters.** An earlier version tracked only ESTAB,
# SYN-SENT and CLOSE-WAIT while the engine asked `ss` for `state
# connected`, which also returns TIME-WAIT, FIN-WAIT and LAST-ACK. The
# query and the parser disagreed, so real rows were silently dropped —
# caught by a smoke check written minutes earlier, on Linux, before the
# Windows disc was even built.
#
# For threat matching the wider set is also the *correct* one: a
# TIME-WAIT socket means this machine finished talking to that peer
# moments ago, which is exactly what a C2 beacon looks like between
# check-ins. Only tracking live sockets would miss the pattern.
TRACKED_STATES = (
    "ESTAB", "ESTABLISHED",
    "SYN-SENT", "SYN_SENT", "SYN-RECV", "SYN_RECV",
    "FIN-WAIT-1", "FIN_WAIT_1", "FIN-WAIT-2", "FIN_WAIT_2",
    "TIME-WAIT", "TIME_WAIT", "CLOSE-WAIT", "CLOSE_WAIT",
    "LAST-ACK", "LAST_ACK", "CLOSING",
)

# Address families that carry a routable peer.
PROTOCOLS = ("tcp", "udp")


@dataclass(frozen=True)
class Connection:
    """One observed socket with a remote peer."""

    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str = ""
    # The owning process, when the OS will say without elevation. Often
    # absent: `ss -p` needs root for other users' sockets. Absence is
    # recorded as empty rather than guessed, because attributing a
    # connection to the wrong process is worse than not naming one.
    process: str = ""
    pid: Optional[int] = None
    observed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self):
        if self.protocol not in PROTOCOLS:
            raise ValueError(f"unknown protocol: {self.protocol!r}")
        if not self.remote_address:
            raise ValueError("a connection without a peer is not a connection")

    @property
    def peer(self) -> str:
        return f"{self.remote_address}:{self.remote_port}"

    @property
    def is_loopback(self) -> bool:
        """Traffic that never left the machine.

        Excluded from threat matching: a blocklist describes the
        internet, and matching it against 127.0.0.1 would be a category
        error, not a detection.
        """
        return (
            self.remote_address.startswith("127.")
            or self.remote_address in ("::1", "0.0.0.0", "::")
        )

    @property
    def is_private(self) -> bool:
        """RFC1918 / link-local / CGNAT — the local network.

        Kept separate from loopback because the two mean different
        things: loopback is this machine, private is the LAN, and a
        connection to the LAN is interesting for shadow-IT questions
        while being useless for internet threat feeds.
        """
        address = self.remote_address
        if address.startswith(("10.", "192.168.", "169.254.", "fe80:", "fc", "fd")):
            return True
        if address.startswith("172."):
            try:
                second = int(address.split(".")[1])
            except (IndexError, ValueError):
                return False
            return 16 <= second <= 31
        if address.startswith("100."):
            try:
                second = int(address.split(".")[1])
            except (IndexError, ValueError):
                return False
            return 64 <= second <= 127   # CGNAT
        return False

    @property
    def is_external(self) -> bool:
        """Whether this peer is out on the internet.

        The only connections a threat feed has any business judging.
        """
        return not (self.is_loopback or self.is_private)

    def to_dict(self) -> dict:
        return asdict(self)
