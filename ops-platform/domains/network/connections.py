"""Parsing observed connections into contracts.

Two operating systems, two genuinely different formats, **two parsers**.

Linux `ss -tunH` gives whitespace columns:

    tcp   ESTAB  0  0   192.168.1.10:54321   93.184.216.34:443

Windows `Get-NetTCPConnection | ConvertTo-Json` gives objects. Writing
one clever parser for both would mean inventing a shape neither OS
produces and translating twice. Two small honest parsers are easier to
read and easier to be wrong about visibly.

**IPv6 is why the address split is not `.rsplit(":")`.** A peer of
`[2606:4700::1111]:443` has eight colons, and splitting on the last one
happens to work while splitting naively does not. That is the kind of
detail that passes every test written on IPv4 and fails on the first
real machine with IPv6, so it is handled here and tested directly.
"""

from typing import List

from contracts.connection import TRACKED_STATES, Connection

# ss uses these; PowerShell says "Established". Normalised on the way in
# so the contract sees one vocabulary rather than each OS's dialect.
# ss writes `TIME-WAIT`, PowerShell writes `TimeWait`. Normalised on the
# way in so the contract sees one vocabulary rather than each OS's
# dialect, and so a state comparison never depends on which tool ran.
_STATE_NAMES = {
    "estab": "ESTABLISHED", "established": "ESTABLISHED",
    "syn-sent": "SYN_SENT", "syn_sent": "SYN_SENT", "synsent": "SYN_SENT",
    "syn-recv": "SYN_RECV", "syn_recv": "SYN_RECV",
    "fin-wait-1": "FIN_WAIT_1", "fin_wait_1": "FIN_WAIT_1",
    "fin-wait-2": "FIN_WAIT_2", "fin_wait_2": "FIN_WAIT_2",
    "time-wait": "TIME_WAIT", "time_wait": "TIME_WAIT", "timewait": "TIME_WAIT",
    "close-wait": "CLOSE_WAIT", "close_wait": "CLOSE_WAIT",
    "closewait": "CLOSE_WAIT",
    "last-ack": "LAST_ACK", "last_ack": "LAST_ACK",
    "closing": "CLOSING",
}


def parse_linux(text: str) -> List[Connection]:
    """Parse `ss -tunH` output. Malformed lines are skipped, not fatal."""
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        parsed = _linux_row(parts)
        if parsed is not None:
            connections.append(parsed)
    return connections


def _linux_row(parts: List[str]):
    """One `ss` row: netid state recv-q send-q local peer."""
    protocol, state = parts[0].lower(), parts[1]
    if protocol not in ("tcp", "udp"):
        return None
    if state.upper() not in [s.upper() for s in TRACKED_STATES]:
        return None

    local_address, local_port = _split_endpoint(parts[4])
    remote_address, remote_port = _split_endpoint(parts[5])
    if not remote_address or remote_port is None:
        return None

    try:
        return Connection(
            protocol=protocol,
            local_address=local_address,
            local_port=local_port or 0,
            remote_address=remote_address,
            remote_port=remote_port,
            state=_normalise_state(state),
        )
    except ValueError:
        return None


def parse_macos(text: str) -> List[Connection]:
    """Parse BSD `netstat -anv -p tcp` (macOS). Malformed lines are skipped.

    Written from a real macOS run, because the Linux `ss` parser matched
    ZERO of fourteen rows on it — silently, which is the worst way to be
    wrong. Three differences from `ss`, each fatal to the Linux parser:

        Proto  Recv-Q Send-Q  Local Address     Foreign Address     (state)
        tcp4   0      0        10.0.2.15.49215   17.188.185.133.5223 ESTABLISHED

      - the protocol is `tcp4`/`tcp6`, not `tcp`;
      - the port joins the address with a DOT, not a colon
        (`10.0.2.15.49215`, and `fe80::1.443` for IPv6);
      - the state is the SIXTH column, and there are header lines to skip.
    """
    connections = []
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        proto = parts[0].lower()
        if not (proto.startswith("tcp") or proto.startswith("udp")):
            continue                       # skips the 'Active'/'Proto' headers
        parsed = _macos_row(parts)
        if parsed is not None:
            connections.append(parsed)
    return connections


def _macos_row(parts: List[str]):
    """One BSD `netstat` row: proto recvq sendq local foreign state ..."""
    protocol = "udp" if parts[0].lower().startswith("udp") else "tcp"
    state = parts[5]
    if state.upper() not in [s.upper() for s in TRACKED_STATES]:
        return None                        # LISTEN and friends are not connections

    local_address, local_port = _split_bsd_endpoint(parts[3])
    remote_address, remote_port = _split_bsd_endpoint(parts[4])
    if not remote_address or remote_port is None:
        return None

    try:
        return Connection(
            protocol=protocol,
            local_address=local_address,
            local_port=local_port or 0,
            remote_address=remote_address,
            remote_port=remote_port,
            state=_normalise_state(state),
            # The pid is column nine when present; best-effort, never required.
            pid=_maybe_int(parts[8]) if len(parts) > 8 else None,
        )
    except ValueError:
        return None


def _split_bsd_endpoint(text: str):
    """Split `address.port` (BSD netstat), surviving IPv6 and wildcards.

    The port is after the LAST dot: `10.0.2.15.49215` -> (10.0.2.15, 49215),
    `fe80::1.443` -> (fe80::1, 443), `*.*` -> (*, 0), `*.8080` -> (*, 8080).
    Splitting on the last dot is correct even for IPv6 because the address
    half keeps its colons untouched.
    """
    text = (text or "").strip()
    if "." not in text:
        return text, None
    address, _, port = text.rpartition(".")
    if port == "*":
        return address, 0
    try:
        return address, int(port)
    except ValueError:
        return address, None


def parse_windows(payload) -> List[Connection]:
    """Parse `Get-NetTCPConnection | ConvertTo-Json` output.

    A single connection serialises as one object rather than a list —
    the classic Windows-only parse bug. The command already wraps in
    `@(...)`, and this accepts both shapes anyway, because relying on
    the caller to have got that right is how it breaks in eighteen
    months when someone edits the command.
    """
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []

    connections = []
    for row in payload:
        parsed = _windows_row(row)
        if parsed is not None:
            connections.append(parsed)
    return connections


def _windows_row(row):
    if not isinstance(row, dict):
        return None
    remote = str(row.get("RemoteAddress") or "")
    if not remote:
        return None
    try:
        return Connection(
            protocol="tcp",   # Get-NetTCPConnection is TCP by definition
            local_address=str(row.get("LocalAddress") or ""),
            local_port=int(row.get("LocalPort") or 0),
            remote_address=remote,
            remote_port=int(row.get("RemotePort") or 0),
            state=_normalise_state(str(row.get("State") or "")),
            pid=_maybe_int(row.get("OwningProcess")),
        )
    except (ValueError, TypeError):
        return None


def _split_endpoint(text: str):
    """Split `address:port`, surviving IPv6.

    `[2606:4700::1111]:443` and `93.184.216.34:443` both have to work,
    and `rsplit(":", 1)` is correct for both — but only because the
    IPv6 form brackets its address. The bracket-stripping is what makes
    that true, so it is not an incidental detail.
    """
    text = (text or "").strip()
    if ":" not in text:
        return text, None

    address, _, port = text.rpartition(":")
    address = address.strip("[]")
    if port == "*":
        return address, 0
    try:
        return address, int(port)
    except ValueError:
        return address, None


def _normalise_state(state: str) -> str:
    return _STATE_NAMES.get((state or "").strip().lower(), (state or "").upper())


def _maybe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
