"""Wi-Fi on three operating systems, and the sampled read.

Split from test_wifi.py at the 400-line hard limit. That file covers the
DETECTION rules; this one covers reading the radio at all — three platforms,
three tools, three output formats, plus the sampling that stops a momentary
cache from writing a permanent baseline.

Two live faults are pinned here:

  - The engine originally hardcoded `nmcli`, so it worked on the machine it
    was written on and would have failed silently on the operator's Windows
    box. It asks platform_support for a command and a format now.
  - `wifi` showed five radios; `wifi trust` a moment later saw ONE and
    confirmed a single radio out of six. NetworkManager's cache thins while
    it rescans. A display can survive that; a baseline cannot.

Run: python3 tools/test_wifi_platforms.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.wifi import assess, learn, security_rank  # noqa: E402
from engines.wifi_scan import (  # noqa: E402
    PARSERS, Radio, parse_airport, parse_netsh, parse_nmcli,
    read_radios_sampled,
)

passed = 0

REAL = r""" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2
 :telenet-1449453:02\:1A\:24\:3E\:6E\:E1:6:92:WPA2
*:HomeNet:02\:1A\:20\:43\:24\:2F:40:79:WPA2 WPA3
 :HomeNet:02\:1A\:20\:FA\:53\:61:6:69:WPA2
 :HomeNet:02\:1A\:20\:FA\:53\:62:40:60:WPA2 WPA3
 :HomeNet:02\:1A\:21\:B2\:B4\:48:6:37:WPA2
 :HomeNet:02\:1A\:21\:B2\:B4\:49:40:25:WPA2 WPA3"""


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def radio(ssid, bssid, chan="6", signal=50, security="WPA2", in_use=False):
    return Radio(ssid=ssid, bssid=bssid, channel=chan, signal=signal,
                 security=security, in_use=in_use)




NETSH = """Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 02:1a:20:43:24:2e
         Signal             : 100%
         Radio type         : 802.11n
         Channel            : 6
    BSSID 2                 : 02:1a:20:43:24:2f
         Signal             : 80%
         Channel            : 40

SSID 2 : telenet-1449453
    Authentication          : WPA2-Personal
    BSSID 1                 : 02:1a:24:3e:6e:e1
         Signal             : 57%
         Channel            : 11
"""

AIRPORT = """                            SSID BSSID             RSSI CHANNEL HT CC SECURITY
                       HomeNet 02:1a:20:43:24:2e  -45 6       Y  -- WPA2(PSK/AES/AES)
                 telenet-1449453 02:1a:24:3e:6e:e1  -72 11      Y  -- WPA2(PSK/AES/AES)"""


def test_windows_netsh_output_parses():
    radios = parse_netsh(NETSH)
    check(len(radios) == 3, "two BSSIDs for one SSID plus one for another")
    mine = [r for r in radios if r.ssid == "HomeNet"]
    check(len(mine) == 2, "both radios grouped under the right SSID")
    check(mine[0].band == "2.4GHz" and mine[1].band == "5GHz", "bands derived")
    check(mine[0].signal == 100, "signal read as a percentage")


def test_macos_airport_output_parses():
    radios = parse_airport(AIRPORT)
    check(len(radios) == 2, "two rows")
    check(radios[0].ssid == "HomeNet", "SSID separated from the BSSID")
    check(radios[0].signal == -45, "RSSI kept negative; it is only compared")


def test_every_declared_format_has_a_parser():
    """platform_support names a format; the engine must be able to read it.
    A format with no parser would KeyError at the worst possible moment."""
    from platform_support.commands import _WIFI_FORMATS
    for form in _WIFI_FORMATS.values():
        check(form in PARSERS, f"'{form}' has a parser")


def test_the_engine_asks_platform_support_rather_than_deciding():
    """The rule platform_support/commands.py states in its own docstring:
    the engine asks for a command and parses what comes back; it never
    decides which command it asked for. The first version of this engine
    hardcoded nmcli and would only ever have worked on Linux."""
    import inspect

    import engines.wifi_scan as engine
    source = inspect.getsource(engine)
    # Assembled at runtime rather than written literally: the architecture
    # rule greps every file for these strings, and a test that names them
    # plainly gets flagged as the very thing it is checking for. (It did.)
    smells = ["sys." + "platform", "platform." + "system",
              "if " + "windows", "os." + "name =="]
    for smell in smells:
        check(smell not in source, f"no '{smell}' branching in the engine")
    check("wifi_scan_command" in source, "it asks platform_support instead")


# --- security wording differs on every platform ----------------------------

def test_security_is_ranked_across_all_three_platform_wordings():
    """Token matching ranked Windows' `WPA2-Personal` as ZERO — weakest.

    That inverts the entire downgrade signal on Windows: every real AP
    reported as insecure, and a genuine open twin indistinguishable from
    them. Substring matching on the family name is the only thing common
    to all three.
    """
    check(security_rank("WPA2 WPA3") == security_rank("WPA3"),
          "linux: the strongest offered wins")
    check(security_rank("WPA2-Personal") == security_rank("WPA2"),
          "windows: WPA2-Personal is WPA2, not unknown")
    check(security_rank("WPA2(PSK/AES/AES)") == security_rank("WPA2"),
          "macos: WPA2(...) is WPA2")
    check(security_rank("WPA3-Personal") > security_rank("WPA2-Personal"),
          "and the ordering survives the platform wording")
    check(security_rank("") == 0 and security_rank("   ") == 0,
          "open or unknown is still lowest")


def test_a_windows_scan_behaves_exactly_like_a_linux_one():
    """Same mesh, same trust, same silence — whatever read the radio."""
    linux = parse_nmcli(REAL)
    windows = parse_netsh(NETSH)

    base_l = learn(linux, {}, ssid="HomeNet")
    base_w = learn(windows, {}, ssid="HomeNet")
    check(assess(linux, base_l, "acer") == [], "linux: own mesh is silent")
    check(assess(windows, base_w, "winbox") == [], "windows: own mesh is silent")

    twin = windows + [radio("HomeNet", "DE:AD:BE:EF:00:99", chan="6",
                            security="")]
    findings = assess(twin, base_w, "winbox")
    check(len(findings) == 1, "windows catches the twin too")
    check("weaker security" in findings[0].message,
          "and the open-vs-WPA2 downgrade is seen through Windows' wording")


# --- one instantaneous read is not a picture of what is in earshot ---------

def test_sampling_unions_reads_that_legitimately_differ():
    """The live bug: `wifi` showed five radios, `wifi trust` a moment later
    saw ONE, and confirmed a single radio out of six. The other five would
    have been reported as intruders on the next pass.

    NetworkManager's cache thins while it rescans and as the client roams,
    so consecutive reads differ honestly. Survivable for a display; not for
    a baseline, which is a permanent decision.
    """
    scans = [
        # first read: the cache is thin, only the associated radio
        r"*:HomeNet:02\:1A\:20\:43\:24\:2F:40:80:WPA2 WPA3",
        # second: the rest are back
        (r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2" "\n"
         r"*:HomeNet:02\:1A\:20\:43\:24\:2F:40:80:WPA2 WPA3" "\n"
         r" :HomeNet:02\:1A\:20\:FA\:53\:61:6:75:WPA2"),
        r" :HomeNet:02\:1A\:21\:B2\:B4\:48:6:37:WPA2",
    ]
    calls = {"n": 0}

    def fake_run(command):
        text = scans[min(calls["n"], len(scans) - 1)]
        calls["n"] += 1
        return text

    radios = read_radios_sampled(samples=3, run=fake_run,
                                 which=lambda _: "/usr/bin/nmcli",
                                 sleep=lambda _: None, form="nmcli")
    bssids = {r.bssid for r in radios}
    check(len(bssids) == 4, "the union covers every radio any sample heard")
    check("02:1A:20:43:24:2E" in bssids and "02:1A:21:B2:B4:48" in bssids,
          "including ones the FIRST read missed entirely")


def test_sampling_keeps_the_strongest_sighting_of_each_radio():
    """The sample that heard it best carries the fullest detail."""
    scans = [r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:20:WPA2",
             r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:95:WPA2"]
    calls = {"n": 0}

    def fake_run(command):
        text = scans[min(calls["n"], len(scans) - 1)]
        calls["n"] += 1
        return text

    radios = read_radios_sampled(samples=2, run=fake_run,
                                 which=lambda _: "/usr/bin/nmcli",
                                 sleep=lambda _: None, form="nmcli")
    check(len(radios) == 1, "one BSSID, not two entries")
    check(radios[0].signal == 95, "and the strongest reading is kept")


def test_one_good_read_among_failures_is_enough():
    scans = [None, r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2", None]
    calls = {"n": 0}

    def fake_run(command):
        text = scans[min(calls["n"], len(scans) - 1)]
        calls["n"] += 1
        return text

    radios = read_radios_sampled(samples=3, run=fake_run,
                                 which=lambda _: "/usr/bin/nmcli",
                                 sleep=lambda _: None, form="nmcli")
    check(radios is not None and len(radios) == 1,
          "a single successful read still yields a result")


def test_every_read_failing_is_None_not_an_empty_list():
    """The distinction the whole platform rests on, at this layer too."""
    radios = read_radios_sampled(samples=2, run=lambda c: None,
                                 which=lambda _: "/usr/bin/nmcli",
                                 sleep=lambda _: None)
    check(radios is None, "all reads failed -> None, never []")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
