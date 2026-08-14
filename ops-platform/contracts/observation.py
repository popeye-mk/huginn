"""Observation — what one host saw on the LAN, at one moment.

The unit of corroboration. Every guard finding this platform makes rests on
a single machine's ARP cache, and a single cache is exactly what an
ARP-spoofing attacker rewrites. The tool has always said so honestly
("confidence: likely", "the packets were not captured") — but honesty about
a blind spot does not remove it.

Two hosts each holding their own cache can *disagree*, and the disagreement
is worth more than either reading alone. That is the entire idea: not more
detectors, a second witness.

Deliberately a plain, portable record:

- **It travels as a file.** No agent, no listener, no port. A host writes
  its observation; another host reads it if it can see it. Loopback-only
  survives intact, because nothing is ever accepted over the network.
- **It carries its own timestamp**, because a stale observation is not
  evidence about now, and a comparison that ignored age would silently
  corroborate the present with the past.
- **It carries `machine_id`**, because "two observations" that turn out to
  be the same host twice is not corroboration at all.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Observation:
    """One host's reading of the segment it is attached to."""

    machine_id: str
    observed_at: str                       # ISO 8601, UTC
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    dhcp_server: Optional[str] = None
    #: ip -> mac, as this host's neighbour table holds it.
    neighbours: Dict[str, str] = field(default_factory=dict)
    local_networks: List[str] = field(default_factory=list)

    #: None means the reading FAILED, and is never the same as an empty
    #: table. A host that could not read its neighbours must not look like a
    #: host that read them and found nothing.
    readable: bool = True

    def to_dict(self) -> dict:
        return {
            "machine_id": self.machine_id,
            "observed_at": self.observed_at,
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "dhcp_server": self.dhcp_server,
            "neighbours": dict(self.neighbours),
            "local_networks": list(self.local_networks),
            "readable": self.readable,
        }

    @staticmethod
    def from_dict(data: dict) -> "Observation":
        """Rebuild from disk. Tolerant: a malformed field degrades, never raises.

        The file may have been written by a different version on a different
        OS. Refusing to parse it would turn a second witness into an
        outage; reading what is there and marking the rest unknown keeps the
        useful part.
        """
        data = data or {}
        neighbours = data.get("neighbours")
        if not isinstance(neighbours, dict):
            neighbours = {}
        networks = data.get("local_networks")
        if not isinstance(networks, list):
            networks = []
        return Observation(
            machine_id=str(data.get("machine_id") or "unknown"),
            observed_at=str(data.get("observed_at") or ""),
            gateway_ip=data.get("gateway_ip") or None,
            gateway_mac=(data.get("gateway_mac") or None),
            dhcp_server=data.get("dhcp_server") or None,
            neighbours={str(k): str(v) for k, v in neighbours.items()},
            local_networks=[str(n) for n in networks],
            readable=bool(data.get("readable", True)),
        )
