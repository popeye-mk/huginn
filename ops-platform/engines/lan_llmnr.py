"""LLMNR / mDNS name-resolution poisoning probe (G8).

The attack this catches: a Responder-style host on the LAN answers LLMNR
(UDP 5355) and mDNS (UDP 5353) name queries for names it has no business
owning, poisoning name resolution to harvest credentials. It is one of the
classic switched-LAN attacks a joined host CAN see — the same category as
ARP spoofing and rogue DHCP.

**How we detect it without root or a packet tap:** ask for a name that
cannot exist. We send an LLMNR and an mDNS query for a fresh random label
(e.g. `zq7f3k9x2m1p`). On an honest LAN *nothing* answers — no host has that
name. A poisoner answers everything, so **any** reply to our decoy is the
tell. This is active (we send a probe), standard (a normal name query), on
the operator's own LAN only, and needs no privileges — the same posture as
the exposure scan.

Everything network-facing goes through an injectable `transport`, so the
packet build/parse and the assessment are unit-tested without a socket; the
real multicast send/recv is the thin part, verified on a real LAN.
"""

import os
import random
import socket
import string
import struct
from dataclasses import dataclass
from typing import List, Optional

LLMNR_ADDR, LLMNR_PORT = "224.0.0.252", 5355
MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353
# NBT-NS is broadcast, not multicast, and the Windows-heavy Responder vector.
NBTNS_ADDR, NBTNS_PORT = "255.255.255.255", 137


@dataclass(frozen=True)
class Responder:
    """A host that answered a query for a name that does not exist."""

    ip: str
    proto: str        # "LLMNR" | "mDNS"
    name: str         # the decoy name it falsely claimed


def random_name(n: int = 12) -> str:
    """A label random enough that no real host will legitimately own it."""
    return "".join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(n))


def build_query(labels: List[str], txid: int) -> bytes:
    """A minimal DNS-format query (LLMNR and mDNS share the wire format).

    Header: id, flags=0 (standard query), qdcount=1, others 0. Question:
    the labels length-prefixed and null-terminated, qtype=A(1), qclass=IN(1).
    """
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0000, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    return header + q + struct.pack(">HH", 1, 1)


def nbt_encode(name: str, suffix: int = 0x00) -> bytes:
    """NetBIOS first-level encoding: a 16-byte name → 32 ASCII bytes.

    The NetBIOS name is 15 chars (uppercased, space-padded) plus a 1-byte
    suffix (0x00 = workstation). Each byte is split into two nibbles, each
    added to 'A' — the encoding NBT-NS puts on the wire."""
    raw = name.upper()[:15].ljust(15).encode("ascii") + bytes([suffix & 0xFF])
    out = bytearray()
    for b in raw:
        out.append((b >> 4) + 0x41)
        out.append((b & 0x0F) + 0x41)
    return bytes(out)


def build_nbtns_query(name: str, txid: int) -> bytes:
    """A NBT-NS name-query request for `name`.

    Same 12-byte header shape as DNS (so `is_answer_for` parses the reply),
    but a NetBIOS-encoded question: flags 0x0110 (broadcast + recursion
    desired), qtype NB (0x0020), qclass IN (0x0001)."""
    header = struct.pack(">HHHHHH", txid & 0xFFFF, 0x0110, 1, 0, 0, 0)
    question = bytes([0x20]) + nbt_encode(name) + b"\x00"
    return header + question + struct.pack(">HH", 0x0020, 0x0001)


def is_answer_for(data: bytes, txid: int) -> bool:
    """True if `data` is a response to our query id carrying an answer.

    We only need "did anyone answer our bogus name," not what they claimed:
    the QR bit set, our transaction id, and ancount > 0."""
    if len(data) < 12:
        return False
    rid, flags, _qd, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != (txid & 0xFFFF):
        return False
    if not (flags & 0x8000):            # QR bit: this is a response
        return False
    return ancount > 0


class _MulticastTransport:
    """The real send/recv. Kept thin; the logic lives in pure functions."""

    def exchange(self, packet, addr, port, timeout):
        """Send `packet` to (addr, port); return (src_ip, raw) for each reply."""
        out = []
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                 socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            # NBT-NS goes to the broadcast address; harmless for multicast.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (addr, port))
            end = _monotonic() + timeout
            while _monotonic() < end:
                try:
                    data, src = sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError:
                    break
                out.append((src[0], data))
        except OSError:
            return []                    # can't open/send: caller degrades
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return out


def _monotonic():
    import time
    return time.monotonic()


def available() -> bool:
    """Whether we can open a UDP socket to probe. Best-effort, never raises."""
    if os.environ.get("HUGINN_NO_NET"):
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.close()
        return True
    except OSError:
        return False


def probe(transport=None, name: Optional[str] = None, timeout: float = 2.0) -> List[Responder]:
    """Send a decoy LLMNR + mDNS query and return whoever answered it.

    On an honest LAN this is an empty list. Any `Responder` returned is a
    host claiming a name that does not exist — a poisoner.
    """
    transport = transport or _MulticastTransport()
    name = name or random_name()
    responders: List[Responder] = []

    # (proto, addr, port, shown-name, packet) for each of the three vectors.
    txid = random.randint(0, 0xFFFF)
    probes = (
        ("LLMNR", LLMNR_ADDR, LLMNR_PORT, name,
         build_query([name], txid)),
        ("mDNS", MDNS_ADDR, MDNS_PORT, f"{name}.local",
         build_query([name, "local"], txid ^ 0x0001)),
        ("NBT-NS", NBTNS_ADDR, NBTNS_PORT, name.upper()[:15],
         build_nbtns_query(name, txid ^ 0x0002)),
    )
    for i, (proto, addr, port, shown, packet) in enumerate(probes):
        expect = txid ^ i                       # the id this packet carries
        try:
            replies = transport.exchange(packet, addr, port, timeout)
        except Exception:  # noqa: BLE001 - a broken transport is "not checked"
            replies = []
        for ip, data in replies or []:
            if is_answer_for(data, expect):
                responders.append(Responder(ip=ip, proto=proto, name=shown))
    return responders
