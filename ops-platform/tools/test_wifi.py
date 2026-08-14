"""Tests for Wi-Fi evil-twin detection (chapter two, item 6).

The parsing tests use the operator's REAL `nmcli -t` output, captured from
his machine before a line of this was written. Two things in it shaped the
whole feature:

  - `nmcli -t` escapes the colons INSIDE fields (`0C\\:72\\:74\\:...`).
    `line.split(":")` shreds every BSSID into six fragments and produces
    confident nonsense without raising.
  - His SSID has SIX legitimate BSSIDs — three dual-band APs in a mesh. The
    obvious rule, "known SSID on an unknown BSSID", would have fired on his
    own equipment every hour, which is how an operator learns to ignore an
    alert. Detection is against a CONFIRMED BSSID list instead.

Run: python3 tools/test_wifi.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.wifi import (  # noqa: E402
    assess, forget, learn, security_rank, unchecked, unknown_radios,
)
from engines.wifi_scan import (  # noqa: E402
    PARSERS, Radio, parse_airport, parse_iw, parse_netsh, parse_nmcli,
    read_radios_sampled, split_nmcli,
)

passed = 0

#: Captured verbatim from the operator's laptop, 2026-07-27.
REAL = r""" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2
 :telenet-1449453:02\:1A\:24\:3E\:6E\:E1:6:92:WPA2
*:HomeNet:02\:1A\:20\:43\:24\:2F:40:79:WPA2 WPA3
 :HomeNet:02\:1A\:20\:FA\:53\:61:6:69:WPA2
 :HomeNet:02\:1A\:20\:FA\:53\:62:40:60:WPA2 WPA3
 :TelenetWiFree:02\:1A\:22\:93\:20\:CC:6:44:WPA2 802.1X
 :HomeNet:02\:1A\:21\:B2\:B4\:48:6:37:WPA2
 :telenet-944A4:02\:1A\:26\:77\:08\:2B:6:32:WPA2
 ::02\:1A\:25\:77\:08\:08:108:27:WPA2
 :HomeNet:02\:1A\:21\:B2\:B4\:49:40:25:WPA2 WPA3
 :telenet-320C4:02\:1A\:2E\:93\:20\:CA:36:12:WPA2"""


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def radio(ssid, bssid, chan="6", signal=50, security="WPA2", in_use=False):
    return Radio(ssid=ssid, bssid=bssid, channel=chan, signal=signal,
                 security=security, in_use=in_use)


# --- parsing real output ---------------------------------------------------

def test_the_escaped_colons_do_not_shred_the_bssid():
    """The bug a naive split produces silently, with no exception."""
    fields = split_nmcli(r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2")
    check(fields[2] == "02:1A:20:43:24:2E", "the BSSID survives intact")
    check(len(r" :HomeNet:02\:1A\:20\:43\:24\:2E:6:100:WPA2".split(":")) > 6,
          "whereas a naive split really does produce more than six fields")


def test_the_operators_real_scan_parses_completely():
    radios = parse_nmcli(REAL)
    check(len(radios) == 11, "all eleven rows parsed")
    check(len([r for r in radios if r.ssid == "HomeNet"]) == 6,
          "and his SSID really does have six legitimate BSSIDs")
    check([r.bssid for r in radios if r.in_use] == ["02:1A:20:43:24:2F"],
          "the associated radio is identified")


def test_bands_are_derived_from_the_channel():
    radios = {r.bssid: r for r in parse_nmcli(REAL)}
    check(radios["02:1A:20:43:24:2E"].band == "2.4GHz", "ch 6 is 2.4GHz")
    check(radios["02:1A:20:43:24:2F"].band == "5GHz", "ch 40 is 5GHz")


def test_a_nameless_radio_is_hidden_not_empty():
    hidden = [r for r in parse_nmcli(REAL) if r.hidden]
    check(len(hidden) == 1 and hidden[0].bssid == "02:1A:25:77:08:08",
          "the hidden network is recognised as hidden")


def test_an_unreadable_scan_is_None_and_an_empty_one_is_a_list():
    check(parse_nmcli(None) is None, "unreadable -> None")
    check(parse_nmcli("") == [], "heard nothing -> empty list, NOT None")
    check(parse_iw(None) is None, "same rule for the iw fallback")


def test_iw_output_parses_as_a_fallback():
    radios = parse_iw("BSS 02:1a:20:43:24:2f(on wlp8s0) -- associated\n"
                      "\tfreq: 5200\n\tsignal: -45.00 dBm\n\tSSID: HomeNet\n")
    check(len(radios) == 1, "one BSS block")
    check(radios[0].ssid == "HomeNet" and radios[0].in_use,
          "ssid and association read from the iw form")
    check(radios[0].band == "5GHz", "5200 MHz is 5GHz")


# --- the mesh problem, which is the whole design ---------------------------

def test_the_operators_own_mesh_is_SILENT_once_confirmed():
    """Six BSSIDs, one SSID, zero findings. If this fails the feature is
    a noise machine and nobody will read its output."""
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    check(len(baseline["HomeNet"]) == 6, "all six confirmed")
    check(assess(radios, baseline, "acer") == [],
          "and the very same scan then produces NOTHING")


def test_an_unconfirmed_bssid_on_a_trusted_ssid_is_reported():
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    twin = radios + [radio("HomeNet", "DE:AD:BE:EF:00:99", signal=95)]
    findings = assess(twin, baseline, "acer")
    check(len(findings) == 1, "one finding")
    check(findings[0].severity == "warning", "warning, never critical")
    check(findings[0].confidence == "likely",
          "likely: buying a repeater produces this exact signal")
    check("DE:AD:BE:EF:00:99" in findings[0].message, "the BSSID is named")
    check("wifi trust" in findings[0].suggested_action,
          "and the operator is told how to confirm it if it is theirs")


def test_a_STRANGERS_network_on_a_new_bssid_is_ignored():
    """telenet-* is not his. A neighbour's new AP is a neighbour's business."""
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    stranger = radios + [radio("telenet-1449453", "AA:BB:CC:DD:EE:FF")]
    check(assess(stranger, baseline, "acer") == [],
          "only SSIDs the operator confirmed can have a twin")


# --- security compared WITHIN a band ---------------------------------------

def test_security_is_compared_within_a_band_not_across_it():
    """His 2.4GHz is WPA2 and his 5GHz is WPA2 WPA3, legitimately.

    Comparing across bands would report a downgrade on every access point
    he owns — a false positive per AP, per scan.
    """
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    check(assess(radios, baseline, "acer") == [],
          "the real mixed-security mesh raises nothing")

    weaker = radios + [radio("HomeNet", "DE:AD:BE:EF:00:99",
                             chan="6", security="")]
    finding = assess(weaker, baseline, "acer")[0]
    check("weaker security" in finding.message,
          "an OPEN radio on the 2.4GHz band, where his are WPA2, is flagged")
    check("cannot offer security they do not have" in finding.suggested_action,
          "and the reasoning is given: a twin cannot fake WPA3 it lacks")


def test_a_matching_security_twin_is_still_reported_just_without_downgrade():
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    same = radios + [radio("HomeNet", "DE:AD:BE:EF:00:99", security="WPA2")]
    finding = assess(same, baseline, "acer")[0]
    check("weaker security" not in finding.message,
          "no downgrade claimed when the security matches")
    check(finding.severity == "warning", "but it is still an unconfirmed radio")


def test_unknown_security_ranks_lowest():
    """An unfamiliar scheme on your own SSID is worth a look. Treating the
    unknown as strong would hide exactly the case worth seeing."""
    check(security_rank("WPA3") > security_rank("WPA2") > security_rank(""),
          "wpa3 > wpa2 > nothing")
    check(security_rank("SOMETHING-NEW") == 0, "an unrecognised token ranks lowest")


# --- absence is never health -----------------------------------------------

def test_a_failed_scan_produces_no_findings_and_says_why():
    check(assess(None, {"HomeNet": ["AA:BB"]}, "acer") == [],
          "a failed scan produces no findings...")
    check("could not be read" in unchecked(None, {})[0],
          "...and is reported as unchecked, not as clear")


def test_no_baseline_means_nothing_can_be_called_unexpected():
    radios = parse_nmcli(REAL)
    check(assess(radios, {}, "acer") == [], "no baseline -> no findings")
    check("no confirmed radios yet" in unchecked(radios, {})[0],
          "and the reason is stated rather than reading as quiet")


# --- managing the baseline -------------------------------------------------

def test_learning_never_confirms_a_hidden_radio():
    """A nameless radio cannot meaningfully be 'yours'."""
    baseline = learn(parse_nmcli(REAL), {})
    check("" not in baseline, "the hidden SSID is not given a trust entry")


def test_forget_withdraws_trust_and_the_radio_reappears():
    radios = parse_nmcli(REAL)
    baseline = learn(radios, {}, ssid="HomeNet")
    reduced = forget(baseline, "02:1A:21:B2:B4:48")
    check(len(reduced["HomeNet"]) == 5, "one fewer confirmed")
    findings = assess(radios, reduced, "acer")
    check(len(findings) == 1 and "02:1A:21:B2:B4:48" in findings[0].message,
          "and the withdrawn radio is reported from the next scan")


def test_learning_is_idempotent():
    radios = parse_nmcli(REAL)
    once = learn(radios, {}, ssid="HomeNet")
    twice = learn(radios, once, ssid="HomeNet")
    check(once == twice, "confirming the same radios twice changes nothing")


def test_unknown_radios_matches_case_insensitively():
    """A BSSID from a config file may be lower case; the scan is upper."""
    baseline = {"HomeNet": ["02:1a:20:43:24:2e"]}
    found = unknown_radios([radio("HomeNet", "02:1A:20:43:24:2E")], baseline)
    check(found == [], "case must not turn a trusted radio into a stranger")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
