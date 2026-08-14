"""Tests for the unified LAN + Wi-Fi inventory.

The claim this module makes, and the one worth testing hardest: **seen is
not confirmed.** The census baseline learns every device it meets. Read as
"these are my devices" it is eleven entries of nothing — the printer and the
stranger sit in the same undifferentiated list. Only a human act (a label, a
trusted BSSID) counts here.

The Wi-Fi fixtures use the operator's real mesh: one SSID, six BSSIDs. Any
rule that treats his own equipment as suspicious is a rule he will learn to
ignore, so "confirmed radios produce nothing" is asserted directly.

Run: python3 tools/test_inventory.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.inventory import (  # noqa: E402
    LAN, WIFI, build, counts, headline, ignored_radios, lan_items, wifi_items,
)
from engines.wifi_scan import Radio  # noqa: E402

passed = 0

SWEEP = "2026-07-27T08:25:15+00:00"
EARLIER = "2026-07-26T20:10:00+00:00"

#: Three devices: one labelled by hand, one that only reports a hostname,
#: one that has not been seen since yesterday.
BASELINE = {
    "aa:bb:cc:dd:ee:01": {"ip": "192.168.1.10", "vendor": "AVM (Fritz!Box)",
                          "name": "_gateway", "label": "the router",
                          "last_seen": SWEEP},
    "aa:bb:cc:dd:ee:02": {"ip": "192.168.1.20", "vendor": "TP-Link",
                          "name": "kitchen-plug", "last_seen": SWEEP},
    "aa:bb:cc:dd:ee:03": {"ip": "192.168.1.30", "vendor": "randomized MAC",
                          "name": "", "last_seen": EARLIER},
}


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def radio(ssid, bssid, chan="6", signal=50, security="WPA2", in_use=False):
    return Radio(ssid=ssid, bssid=bssid, channel=chan, signal=signal,
                 security=security, in_use=in_use)


# --- the distinction the module exists for ---------------------------------

def test_a_labelled_device_is_confirmed_and_a_named_one_is_NOT():
    """A probed hostname is what the device SAYS about itself.

    The device you cannot account for is exactly the one whose
    self-description you should not accept as identification.
    """
    items = {i.key: i for i in lan_items(BASELINE)}
    check(items["aa:bb:cc:dd:ee:01"].confirmed, "a hand-written label confirms")
    check(not items["aa:bb:cc:dd:ee:02"].confirmed,
          "a probed hostname does NOT confirm, however friendly it looks")
    check(items["aa:bb:cc:dd:ee:02"].note.startswith("answers to"),
          "the probed name is shown, but framed as a claim the device made")


def test_the_label_is_what_gets_displayed():
    items = {i.key: i for i in lan_items(BASELINE)}
    check(items["aa:bb:cc:dd:ee:01"].name == "the router",
          "the operator's own word wins over the probed one")
    check(items["aa:bb:cc:dd:ee:03"].name == "randomized MAC",
          "with neither, the vendor is better than a bare MAC")


def test_presence_is_measured_against_the_LAST_SWEEP_not_the_clock():
    """`present` is a claim about the last census, and dates itself.

    Without this, a baseline that stopped being updated would keep
    reporting a room full of devices as "here now" forever.
    """
    items = {i.key: i for i in lan_items(BASELINE)}
    check(items["aa:bb:cc:dd:ee:01"].present, "seen in the most recent sweep")
    check(not items["aa:bb:cc:dd:ee:03"].present,
          "last seen yesterday is NOT here now")
    stock = build(lan_baseline=BASELINE, radios=[], wifi_baseline={})
    check(stock.as_of == SWEEP, "and the inventory carries WHEN 'now' was")


def test_an_empty_baseline_is_not_a_confirmed_network():
    tally = counts(build(lan_baseline={}, radios=[], wifi_baseline={}))
    check(tally["total"] == 0 and tally["confirmed"] == 0, "nothing either way")
    head = headline(build(lan_baseline={}, radios=[], wifi_baseline={}))
    check(head["state"] == "unknown",
          "an empty inventory is UNKNOWN, never a clean bill of health")


# --- Wi-Fi: the mesh must stay quiet ---------------------------------------

MESH = [
    radio("HomeNet", "02:1A:20:43:24:2E"),
    radio("HomeNet", "02:1A:20:43:24:2F", chan="40", security="WPA2 WPA3",
          in_use=True),
    radio("HomeNet", "02:1A:21:B2:B4:48", signal=37),
    radio("telenet-1449453", "02:1A:24:3E:6E:E1", signal=92),
    radio("TelenetWiFree", "02:1A:22:93:20:CC", signal=44),
]
TRUSTED = {"HomeNet": ["02:1A:20:43:24:2E", "02:1A:20:43:24:2F",
                         "02:1A:21:B2:B4:48"]}


def test_a_fully_confirmed_mesh_shows_no_unconfirmed_radio():
    items = wifi_items(MESH, TRUSTED)
    check(len(items) == 3, "only his own three radios are listed")
    check(all(i.confirmed for i in items), "and every one reads as confirmed")


def test_a_neighbours_network_is_not_listed_but_IS_counted():
    """Silence about a neighbour is a decision, so it is stated."""
    names = {i.name for i in wifi_items(MESH, TRUSTED)}
    check("telenet-1449453" not in names, "a stranger's AP is not his business")
    check(ignored_radios(MESH, TRUSTED) == 2,
          "but the operator is told how many were left out")


def test_an_unconfirmed_radio_on_HIS_ssid_is_listed_and_flagged():
    twin = MESH + [radio("HomeNet", "DE:AD:BE:EF:00:99", signal=95)]
    items = {i.key: i for i in wifi_items(twin, TRUSTED)}
    check("DE:AD:BE:EF:00:99" in items, "the new radio appears")
    check(not items["DE:AD:BE:EF:00:99"].confirmed, "and is unconfirmed")
    check(items["DE:AD:BE:EF:00:99"].confirm_with.startswith("wifi trust"),
          "with the exact command that would confirm it")


def test_a_confirmed_radio_out_of_earshot_is_shown_as_absent_not_missing():
    """An access point in a far room is invisible, and that is fine.

    Dropping it from the list would make the operator's own equipment
    silently disappear from the panel that exists to inventory it.
    """
    baseline = {"HomeNet": list(TRUSTED["HomeNet"]) + ["02:1A:21:B2:B4:49"]}
    items = {i.key: i for i in wifi_items(MESH, baseline)}
    absent = items["02:1A:21:B2:B4:49"]
    check(absent.confirmed and not absent.present, "confirmed, but not here")
    check(absent.note == "out of earshot", "and the reason is given")


def test_with_no_baseline_the_CONNECTED_network_is_offered():
    """Otherwise the panel is blank on the machine that needs it most."""
    items = wifi_items(MESH, {})
    check(items and all(i.name == "HomeNet" for i in items),
          "the network currently associated becomes the starting point")
    check(not any(i.confirmed for i in items),
          "offered is not confirmed — nothing is trusted by being displayed")


# --- absence discipline ----------------------------------------------------

def test_a_failed_wifi_scan_is_carried_not_counted_as_clean():
    stock = build(lan_baseline=BASELINE, radios=None, wifi_baseline=TRUSTED,
                  wifi_readable=False)
    check(stock.unreadable, "the failure is recorded as a stated gap")
    check("not the same as no evil twin" in stock.unreadable[0],
          "in words that refuse the wrong inference")
    check(headline(stock)["state"] == "unknown",
          "and the headline can never be green over a partial read")


def test_an_unreadable_lan_is_reported_too():
    stock = build(lan_baseline={}, radios=MESH, wifi_baseline=TRUSTED,
                  lan_readable=False)
    check(any("no device was checked" in u for u in stock.unreadable),
          "a missing census baseline is a gap, not an empty network")


def test_everything_confirmed_reads_green_only_when_nothing_is_unread():
    labelled = {mac: dict(rec, label="mine") for mac, rec in BASELINE.items()}
    stock = build(lan_baseline=labelled, radios=MESH, wifi_baseline=TRUSTED)
    head = headline(stock)
    check(head["state"] == "ok", "all named, both sources read: ok")
    check(counts(stock)["unconfirmed"] == 0, "and the count agrees")


def test_both_kinds_land_in_one_list_with_one_vocabulary():
    """The point of the whole module: one question, one shape."""
    stock = build(lan_baseline=BASELINE, radios=MESH, wifi_baseline=TRUSTED)
    kinds = {i.kind for i in stock.items}
    check(kinds == {LAN, WIFI}, "LAN devices and radios sit in the same list")
    check(all(hasattr(i, "confirmed") and hasattr(i, "present")
              for i in stock.items),
          "and answer the same two questions in the same words")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
