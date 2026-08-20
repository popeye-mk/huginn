"""Tests for observed connections (R8's missing input).

**Why this exists at all.** Every threat-feed design in R8 assumed the
platform could see what a machine connects to. Nothing could — netdiag
reports `sockets_established` as a *count* with no peers. Matching a
blocklist against that would have been a rule that could never fire, the
same hole as `disk_path` in the boot stage, and it was caught this time
before any matching logic existed.

The tests below are mostly about **what a connection is not allowed to
mean**. An observed peer is a fact, not a verdict; the classification
here only separates "out on the internet" from "this machine" and "this
LAN", because a blocklist describing the internet has no business being
matched against 127.0.0.1.

Run: python3 tools/test_connections.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import Connection  # noqa: E402
from domains.network.connections import (  # noqa: E402
    parse_linux, parse_macos, parse_windows,
)

# Real `ss -tunH state connected` output shape, including the IPv6 form
# with a bracketed address that breaks naive parsing.
SS_OUTPUT = """\
tcp   ESTAB  0      0            192.168.1.10:54321      93.184.216.34:443
tcp   ESTAB  0      0               127.0.0.1:38402          127.0.0.1:6379
tcp   ESTAB  0      0    [2a00:1450:4001::200e]:51234  [2606:4700::1111]:443
udp   ESTAB  0      0            192.168.1.10:68           192.168.1.1:67
tcp   SYN-SENT 0    0            192.168.1.10:44556        140.82.113.4:443
tcp   LISTEN 0      4096            0.0.0.0:3128              0.0.0.0:*
garbage line that should not crash anything
"""

# Real `Get-NetTCPConnection | ConvertTo-Json` shape.
PS_OUTPUT = json.dumps([
    {"LocalAddress": "192.168.1.20", "LocalPort": 51000,
     "RemoteAddress": "20.190.159.4", "RemotePort": 443,
     "State": "Established", "OwningProcess": 4321},
    {"LocalAddress": "127.0.0.1", "LocalPort": 49670,
     "RemoteAddress": "127.0.0.1", "RemotePort": 49671,
     "State": "Established", "OwningProcess": 900},
])


# --- Linux parsing --------------------------------------------------------

def test_linux_output_parses():
    connections = parse_linux(SS_OUTPUT)
    peers = {c.peer for c in connections}
    assert "93.184.216.34:443" in peers
    assert "192.168.1.1:67" in peers


def test_ipv6_peers_survive_the_address_split():
    """`[2606:4700::1111]:443` has eight colons.

    Splitting on the last one is correct only because the address is
    bracketed — a detail that passes every IPv4 test and fails on the
    first real machine with IPv6.
    """
    connections = parse_linux(SS_OUTPUT)
    ipv6 = [c for c in connections if ":" in c.remote_address]
    assert ipv6, "no IPv6 connection parsed"
    assert ipv6[0].remote_address == "2606:4700::1111"
    assert ipv6[0].remote_port == 443


def test_listening_sockets_are_not_connections():
    """A LISTEN row has no peer; netdiag already reports exposure.

    Including them would double-count local exposure as outbound reach,
    which are different questions.
    """
    for connection in parse_linux(SS_OUTPUT):
        assert connection.state != "LISTEN"
        assert connection.remote_address != "0.0.0.0"


def test_a_malformed_line_is_skipped_not_fatal():
    """One bad row must not cost every good one."""
    assert len(parse_linux(SS_OUTPUT)) >= 4
    assert parse_linux("total garbage\n\n") == []
    assert parse_linux("") == []


def test_syn_sent_is_kept():
    """A connection being *attempted* is exactly what matters for C2.

    Malware reaching for a dead server never reaches ESTABLISHED, and
    dropping SYN-SENT would hide the most diagnostic case of all.
    """
    states = {c.state for c in parse_linux(SS_OUTPUT)}
    assert "SYN_SENT" in states


# --- Windows parsing ------------------------------------------------------

def test_windows_output_parses():
    connections = parse_windows(json.loads(PS_OUTPUT))
    assert any(c.peer == "20.190.159.4:443" for c in connections)
    assert any(c.pid == 4321 for c in connections)


def test_a_single_windows_connection_is_not_lost():
    """ConvertTo-Json emits a bare object for one row, not a list.

    The classic Windows-only parse bug: works in testing with two
    connections, silently returns nothing on a quiet machine with one.
    """
    single = json.loads(PS_OUTPUT)[0]
    assert len(parse_windows(single)) == 1


def test_windows_junk_does_not_crash():
    assert parse_windows(None) == []
    assert parse_windows("not json") == []
    assert parse_windows([{"nothing": "useful"}]) == []


# --- what a connection refuses to claim -----------------------------------

def _connection(remote, port=443):
    return Connection(
        protocol="tcp", local_address="192.168.1.10", local_port=1,
        remote_address=remote, remote_port=port, state="ESTABLISHED",
    )


def test_loopback_is_not_external():
    """Matching an internet blocklist against 127.0.0.1 is a category error."""
    for address in ("127.0.0.1", "127.0.1.1", "::1"):
        assert _connection(address).is_loopback
        assert not _connection(address).is_external


def test_private_ranges_are_not_external():
    for address in ("10.1.2.3", "192.168.0.5", "172.16.0.1",
                    "172.31.255.254", "169.254.1.1", "100.64.0.1"):
        assert _connection(address).is_private, address
        assert not _connection(address).is_external, address


def test_public_addresses_are_external():
    for address in ("93.184.216.34", "8.8.8.8", "172.15.0.1",
                    "172.32.0.1", "100.63.0.1", "2606:4700::1111"):
        assert _connection(address).is_external, address


def test_a_connection_without_a_peer_is_rejected():
    """The contract's one hard rule."""
    try:
        Connection(
            protocol="tcp", local_address="0.0.0.0", local_port=80,
            remote_address="", remote_port=0,
        )
    except ValueError as exc:
        assert "peer" in str(exc)
        return
    raise AssertionError("a peerless connection was accepted")


def test_an_unknown_protocol_is_rejected():
    try:
        Connection(
            protocol="carrier-pigeon", local_address="1.1.1.1", local_port=1,
            remote_address="2.2.2.2", remote_port=2,
        )
    except ValueError:
        return
    raise AssertionError("an invented protocol was accepted")


def test_process_absence_is_empty_not_guessed():
    """`ss -p` needs root; attributing to the wrong process is worse."""
    connection = parse_linux(SS_OUTPUT)[0]
    assert connection.process == ""
    assert connection.pid is None


def test_every_connected_state_the_query_asks_for_is_accepted():
    """The engine asks `ss` for `state connected`; the parser must agree.

    Found by a smoke check on Linux: the query returned TIME-WAIT and
    FIN-WAIT rows that the parser silently discarded, so `ss` reported
    connections and the platform reported none. A query and a parser
    that disagree lose data without anyone noticing.

    The wider set is also correct for threat matching — a TIME-WAIT
    socket means this machine finished talking to that peer moments
    ago, which is what a beacon looks like between check-ins.
    """
    rows = "\n".join(
        f"tcp   {state}  0  0   192.168.1.10:5432{i}   93.184.216.{i}:443"
        for i, state in enumerate(
            ["ESTAB", "TIME-WAIT", "FIN-WAIT-1", "FIN-WAIT-2",
             "CLOSE-WAIT", "LAST-ACK", "SYN-SENT", "CLOSING"]
        )
    )
    parsed = parse_linux(rows)
    assert len(parsed) == 8, f"dropped {8 - len(parsed)} connected rows"


def test_windows_state_spelling_is_normalised():
    """PowerShell says `TimeWait`; ss says `TIME-WAIT`. One vocabulary."""
    rows = [{"LocalAddress": "192.168.1.20", "LocalPort": 5100,
             "RemoteAddress": "20.190.159.4", "RemotePort": 443,
             "State": "TimeWait", "OwningProcess": 10}]
    assert parse_windows(rows)[0].state == "TIME_WAIT"


# --- macOS: BSD netstat, captured from a real Mac run ----------------------
#
# The Linux `ss` parser matched ZERO of these rows — silently. This is the
# actual output, headers and all, that exposed it.
MACOS_NETSTAT = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rhiwat shiwat   pid   epid
tcp4       0      0  *.8080                 *.*                    LISTEN       131072 131072   555     0
tcp46      0      0  *.3283                 *.*                    LISTEN       131072 131072   500     0
tcp4       0      0  *.22                   *.*                    LISTEN       131072 131072     1     0
tcp4       0      0  10.0.2.15.49215        17.188.185.133.5223    ESTABLISHED  131072 131400   126   126
tcp6       0      0  fe80::1.51234          fe80::2.443            ESTABLISHED  131072 131072   200     0"""


def test_macos_bsd_netstat_parses():
    """The whole reason for the real-Mac run: this used to yield nothing."""
    conns = parse_macos(MACOS_NETSTAT)
    assert len(conns) == 2, "the two ESTABLISHED rows parse; LISTEN is skipped"


def test_macos_dot_separated_port_is_split_correctly():
    conns = parse_macos(MACOS_NETSTAT)
    c = [x for x in conns if x.remote_port == 5223][0]
    assert c.remote_address == "17.188.185.133", "address keeps its dots, port does not"
    assert c.local_address == "10.0.2.15" and c.local_port == 49215, \
        "the local side splits on the LAST dot too"


def test_macos_ipv6_survives_the_dot_split():
    """`fe80::1.443` — the address half keeps every colon, the port is the tail."""
    conns = parse_macos(MACOS_NETSTAT)
    v6 = [x for x in conns if x.remote_address == "fe80::2"][0]
    assert v6.remote_port == 443 and v6.local_address == "fe80::1", \
        "IPv6 addresses are not shredded by the dot split"


def test_macos_tcp4_and_tcp6_both_become_tcp():
    for c in parse_macos(MACOS_NETSTAT):
        assert c.protocol == "tcp", "tcp4/tcp6 normalise to tcp"


def test_macos_headers_and_garbage_are_skipped_not_fatal():
    assert parse_macos("Active Internet connections\nProto Recv-Q\n") == [], \
        "header-only output is empty, never an error"
    assert parse_macos("") == [], "empty input is empty, not a crash"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
