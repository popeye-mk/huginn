"""Wi-Fi scan reader — what radios are within earshot. Three platforms.

    Linux    nmcli -t ... --rescan no
    Windows  netsh wlan show networks mode=bssid
    macOS    airport -s

**The engine does not know which of those it is running.** It asks
`platform_support.commands` for a command and a format name, runs the one,
parses with the other. The first version hardcoded `nmcli` — which is to
say it was written for one machine and would have failed silently on the
operator's own Windows box. `platform_support/commands.py` states the rule
in its own docstring: keeping the invocation there "stops 'runs on both'
decaying into 'runs on the one I tested'". This is that mistake, and its
correction.

**Reads the CACHE, never triggers a scan.** Every command above returns
what the system already heard. Forcing a fresh scan would transmit probe
requests, and this tool does not transmit — the same rule that keeps the
LAN census reading `ip neigh` rather than sweeping.

**Unprivileged, verified.** nmcli and `iw scan dump` both returned data as
a normal user on the operator's machine; netsh and airport need no
elevation either. A detector that needed root would change what this tool
costs to run, which is a decision rather than an implementation detail.

The parsing trap, found in real output rather than imagined:

    ` :HomeNet:0C\\:72\\:74\\:43\\:24\\:2E:6:100:WPA2`

`nmcli -t` terminates fields with `:` **and escapes the colons inside them
with a backslash**. Splitting naively on `:` shreds every BSSID into six
fragments and silently produces garbage rather than an error.
"""

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional

from contracts.errors import UnsupportedPlatformError
from platform_support.commands import wifi_scan_command, wifi_scan_format

NAME = "wifi_scan"
DEFAULT_TIMEOUT = 15

_IW_BSS = re.compile(r"^BSS ([0-9a-f:]{17})", re.I)
_IW_SSID = re.compile(r"^\s+SSID: (.*)$")
_IW_FREQ = re.compile(r"^\s+freq: (\d+)")
_IW_SIGNAL = re.compile(r"^\s+signal: (-?[\d.]+)")


@dataclass(frozen=True)
class Radio:
    """One BSSID heard by this machine."""

    ssid: str
    bssid: str
    channel: str = ""
    signal: int = 0
    security: str = ""
    in_use: bool = False

    @property
    def band(self) -> str:
        """2.4 or 5 GHz. Which matters: the same AP legitimately offers
        different security on each, so comparing across bands invents
        downgrades that are not there."""
        try:
            return "5GHz" if int(self.channel) > 14 else "2.4GHz"
        except (TypeError, ValueError):
            return "unknown"

    @property
    def hidden(self) -> bool:
        return not self.ssid.strip()


def split_nmcli(line: str) -> List[str]:
    """Split one `nmcli -t` line, honouring backslash-escaped separators.

    Written against the operator's real output. `line.split(":")` turns
    `0C\\:72\\:74\\:43\\:24\\:2E` into six fields and produces confident
    nonsense — the worst kind of parser bug, because nothing raises.
    """
    fields, current, i = [], "", 0
    while i < len(line):
        char = line[i]
        if char == "\\" and i + 1 < len(line):
            current += line[i + 1]
            i += 2
        elif char == ":":
            fields.append(current)
            current = ""
            i += 1
        else:
            current += char
            i += 1
    fields.append(current)
    return fields


def parse_nmcli(text: Optional[str]) -> Optional[List[Radio]]:
    """None means the read FAILED. An empty list means nothing was heard."""
    if text is None:
        return None
    radios = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = split_nmcli(line)
        if len(fields) < 6:
            continue                        # not a scan row; skip, never guess
        in_use, ssid, bssid, chan, signal, security = fields[:6]
        if not re.fullmatch(r"[0-9A-Fa-f:]{17}", bssid or ""):
            continue                        # no BSSID, no radio
        try:
            strength = int(signal)
        except (TypeError, ValueError):
            strength = 0
        radios.append(Radio(ssid=ssid, bssid=bssid.upper(), channel=chan,
                            signal=strength, security=security.strip(),
                            in_use=in_use.strip() == "*"))
    return radios


def parse_iw(text: Optional[str]) -> Optional[List[Radio]]:
    """Fallback parser for `iw dev <if> scan dump`."""
    if text is None:
        return None
    radios, current = [], None
    for line in text.splitlines():
        head = _IW_BSS.match(line)
        if head:
            if current:
                radios.append(_iw_radio(current))
            current = {"bssid": head.group(1).upper(), "ssid": "",
                       "freq": 0, "signal": 0,
                       "in_use": "associated" in line}
            continue
        if current is None:
            continue
        for pattern, key, cast in ((_IW_SSID, "ssid", str),
                                   (_IW_FREQ, "freq", int),
                                   (_IW_SIGNAL, "signal", float)):
            found = pattern.match(line)
            if found:
                try:
                    current[key] = cast(found.group(1))
                except (TypeError, ValueError):
                    pass
    if current:
        radios.append(_iw_radio(current))
    return radios


def _iw_radio(raw: dict) -> Radio:
    freq = raw.get("freq") or 0
    channel = ""
    if 2400 < freq < 2500:
        channel = str(int((freq - 2407) / 5))
    elif freq > 5000:
        channel = str(int((freq - 5000) / 5))
    return Radio(ssid=raw.get("ssid", ""), bssid=raw["bssid"], channel=channel,
                 signal=int(raw.get("signal") or 0),
                 in_use=bool(raw.get("in_use")))



# --- Windows: `netsh wlan show networks mode=bssid` ------------------------
#
# **netsh output is LOCALISED.** On a Dutch or French Windows the labels
# read "Verificatie" or "Authentification", not "Authentication". So the
# structure is parsed, not the prose:
#
#   - `SSID 3 : name` and `BSSID 1 : mac` survive translation, because SSID
#     and BSSID are acronyms rather than words.
#   - Signal is found by its SHAPE (a percentage), not its label.
#   - Channel is found by its shape (a bare number) inside a BSSID block.
#   - Authentication is matched in English and left EMPTY when it is not.
#
# An empty security string ranks lowest, which is the safe direction: on a
# localised Windows every radio reads unknown, so they compare equal and no
# downgrade is invented. Under-claiming beats a false alarm per AP.
_NETSH_SSID = re.compile(r"^\s*SSID\s+\d+\s*:\s*(.*)$", re.I)
_NETSH_BSSID = re.compile(r"^\s*BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})", re.I)
_NETSH_PERCENT = re.compile(r":\s*(\d{1,3})\s*%")
_NETSH_NUMBER = re.compile(r"^\s*\S.*?:\s*(\d{1,3})\s*$")
_NETSH_AUTH = re.compile(r"^\s*Authentication\s*:\s*(.*)$", re.I)


def parse_netsh(text: Optional[str]) -> Optional[List[Radio]]:
    """Parse Windows `netsh wlan show networks mode=bssid`."""
    if text is None:
        return None
    radios: List[Radio] = []
    ssid, security, pending = "", "", None

    def flush():
        if pending:
            radios.append(Radio(ssid=ssid, bssid=pending["bssid"],
                                channel=pending.get("channel", ""),
                                signal=pending.get("signal", 0),
                                security=security))

    for line in text.splitlines():
        head = _NETSH_SSID.match(line)
        if head and not _NETSH_BSSID.match(line):
            flush()
            pending = None
            ssid, security = head.group(1).strip(), ""
            continue

        auth = _NETSH_AUTH.match(line)
        if auth:
            security = auth.group(1).strip()
            continue

        bssid = _NETSH_BSSID.match(line)
        if bssid:
            flush()
            pending = {"bssid": bssid.group(1).upper()}
            continue

        if pending is None:
            continue
        percent = _NETSH_PERCENT.search(line)
        if percent:
            pending["signal"] = int(percent.group(1))
            continue
        number = _NETSH_NUMBER.match(line)
        if number:
            pending["channel"] = number.group(1)

    flush()
    return radios


# --- macOS: `airport -s` ---------------------------------------------------
#
# Removed in macOS 14.4. `is_available` checks the binary exists, so a
# modern Mac reports "could not read" rather than silently returning
# nothing — which would read as "no rogue access points found".
#
#   SSID BSSID             RSSI CHANNEL HT CC SECURITY
#   HomeNet 02:1a:20:43:24:2e  -45 6        Y  -- WPA2(PSK/AES/AES)
_AIRPORT = re.compile(
    r"^\s*(?P<ssid>.*?)\s+(?P<bssid>[0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+"
    r"(?P<rssi>-?\d+)\s+(?P<channel>\d+)", re.I)


def parse_airport(text: Optional[str]) -> Optional[List[Radio]]:
    """Parse macOS `airport -s`."""
    if text is None:
        return None
    radios = []
    for line in text.splitlines():
        found = _AIRPORT.match(line)
        if not found:
            continue
        security = ""
        for token in ("WPA3", "WPA2", "WPA", "WEP", "NONE"):
            if token in line.upper():
                security = "WPA3" if token == "WPA3" else token
                break
        radios.append(Radio(ssid=found.group("ssid").strip(),
                            bssid=found.group("bssid").upper(),
                            channel=found.group("channel"),
                            # RSSI is negative dBm; the domain only ever
                            # compares it, so the sign is kept as-is.
                            signal=int(found.group("rssi")),
                            security="" if security == "NONE" else security))
    return radios


#: format name -> parser. `read_radios` looks up what platform_support
#: DECLARED, rather than sniffing the text: guessing a format from its
#: content is how a parser silently mis-reads a locale it was never shown.
PARSERS = {"nmcli": parse_nmcli, "netsh": parse_netsh, "airport": parse_airport}


def is_available(which=None) -> bool:
    """Whether the scan tool for THIS platform is actually present."""
    finder = which or shutil.which
    try:
        command = wifi_scan_command()
    except UnsupportedPlatformError:
        return False
    binary = command[0]
    # macOS gives an absolute path; `which` will not find it.
    if binary.startswith("/"):
        return os.path.exists(binary)
    return bool(finder(binary))


def read_radios(run=None, which=None,
                interface: str = "", form=None) -> Optional[List[Radio]]:
    """Every radio in earshot, or None if nothing could be read.

    None is NOT an empty list. A machine with no Wi-Fi, an OS with no known
    scan command, or a scan that could not be read must never be reported as
    "no rogue access points found".

    `form` pins the parser instead of deriving it from the host OS. Only a
    test passes it: without it, a test that injects a fake nmcli reading gets
    parsed by whichever parser the RUNNING machine's OS selects — so the same
    injected text passed on Linux and failed on Windows, where `netsh` was
    chosen for `nmcli` output. Injecting the reader but not the parser was a
    half-injected platform, which is not injected at all.
    """
    runner = run or _run

    try:
        command = wifi_scan_command()
        form = form or wifi_scan_format()
    except UnsupportedPlatformError:
        return None

    if not is_available(which):
        return None

    radios = PARSERS[form](runner(command))
    if radios:
        return radios

    # Linux only: `iw` reads the kernel's cached scan when NetworkManager is
    # absent or answered nothing. Kept as a fallback rather than a primary
    # because it needs the interface name and nmcli does not.
    finder = which or shutil.which
    if form == "nmcli" and interface and finder("iw"):
        return parse_iw(runner(["iw", "dev", interface, "scan", "dump"]))

    return radios


def read_radios_sampled(samples: int = 3, delay: float = 1.5, run=None,
                        which=None, interface: str = "",
                        sleep=None, form=None) -> Optional[List[Radio]]:
    """The UNION of several reads, a second or so apart.

    One instantaneous read is not a reliable picture of what is in earshot.
    NetworkManager's cache thins while it is rescanning and as the client
    roams, so consecutive reads legitimately differ — the operator ran
    `wifi` and saw five radios on his SSID, then ran `wifi trust` a moment
    later and the cache offered ONE. He confirmed a single radio, and the
    other four would have been reported as intruders on the next pass.

    That is survivable for a display and not for a baseline: `wifi trust`
    writes a permanent decision, so it must not act on a momentary sample.
    Still passive — this re-reads the same cache, it never asks for a scan.

    Returns None only if EVERY read failed; one good read is enough.
    """
    pause = sleep or time.sleep
    merged, any_read = {}, False
    for index in range(max(1, samples)):
        radios = read_radios(run=run, which=which, interface=interface,
                             form=form)
        if radios is not None:
            any_read = True
            for radio in radios:
                # Keep the strongest sighting of each BSSID: the sample that
                # heard it best is the one with the fullest detail.
                existing = merged.get(radio.bssid)
                if existing is None or radio.signal > existing.signal:
                    merged[radio.bssid] = radio
        if index < samples - 1:
            pause(delay)
    if not any_read:
        return None
    return list(merged.values())


def _run(command) -> Optional[str]:
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                timeout=DEFAULT_TIMEOUT)
    except Exception:                       # noqa: BLE001
        return None
    if result.returncode != 0:
        return None
    return result.stdout
