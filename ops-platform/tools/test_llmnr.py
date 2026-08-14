"""Tests for LLMNR/mDNS name-poisoning detection (G8).

The detection idea is "ask for a name that cannot exist; anyone who answers
is lying." These pin the wire-format build/parse, the decoy probe against an
injected transport (a fake responder that answers, a silent LAN that does
not, and a reply with the wrong id that must be ignored), the assessment
(any responder → one critical finding), and the honest not-checked path.

No socket is opened: the transport is injected. Run: python3 tools/test_llmnr.py
"""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from domains.spoofwatch import assess  # noqa: E402
from engines.lan_llmnr import (  # noqa: E402
    Responder, build_nbtns_query, build_query, is_answer_for, nbt_encode,
    probe, random_name,
)
import skills.namewatch as namewatch  # noqa: E402

passed = 0


def check(cond, msg):
    global passed
    assert cond, msg
    passed += 1


def _response_for(packet, ancount=1):
    """Craft a DNS response echoing the query's txid — what a responder does."""
    txid = struct.unpack(">H", packet[:2])[0]
    return struct.pack(">HHHHHH", txid, 0x8080, 1, ancount, 0, 0) + packet[12:]


class _Responder:
    """A fake poisoner: answers every query, from a fixed IP."""

    def __init__(self, ip="10.0.0.66"):
        self.ip = ip

    def exchange(self, packet, addr, port, timeout):
        return [(self.ip, _response_for(packet))]


class _Silent:
    def exchange(self, packet, addr, port, timeout):
        return []


class _WrongId:
    """Answers, but with a mismatched transaction id — must be ignored."""

    def exchange(self, packet, addr, port, timeout):
        bad = struct.pack(">HHHHHH", 0x1234 ^ 0xFFFF, 0x8080, 1, 1, 0, 0)
        return [("10.0.0.99", bad + packet[12:])]


# --- wire format ----------------------------------------------------------

def test_build_query_is_wellformed():
    q = build_query(["abc", "local"], 0x4142)
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
    check(rid == 0x4142, "txid encoded")
    check(flags == 0 and qd == 1 and an == 0, "standard query, one question")
    check(b"\x03abc\x05local\x00" in q, "labels length-prefixed + null-terminated")
    check(q[-4:] == struct.pack(">HH", 1, 1), "qtype A / qclass IN")


def test_is_answer_for_matches_only_a_real_reply():
    q = build_query(["x"], 0x0700)
    check(is_answer_for(_response_for(q), 0x0700) is True, "QR+txid+answer → yes")
    check(is_answer_for(_response_for(q), 0x0701) is False, "wrong txid → no")
    check(is_answer_for(_response_for(q, ancount=0), 0x0700) is False,
          "a response with no answers is not a poisoning reply")
    check(is_answer_for(q, 0x0700) is False, "the query itself is not a response")
    check(is_answer_for(b"\x00\x00", 0) is False, "a runt packet never crashes")


def test_random_name_is_a_plausible_label():
    n = random_name()
    check(len(n) == 12 and n.isalnum() and n.islower(), "12 lowercase alnum")
    check(random_name() != random_name(), "fresh each call (practically)")


# --- the probe ------------------------------------------------------------

def test_probe_flags_a_responder_on_all_three_protocols():
    r = probe(transport=_Responder("192.168.1.66"), name="zzdecoy")
    check(len(r) == 3, "a responder that answers everything → LLMNR + mDNS + NBT-NS")
    check({x.proto for x in r} == {"LLMNR", "mDNS", "NBT-NS"}, "all three probed")
    check(all(x.ip == "192.168.1.66" for x in r), "responder IP carried")


# --- NBT-NS wire format ---------------------------------------------------

def test_nbt_encode_first_level_encoding():
    # 'FRED' padded to 15 + 0x00 suffix; each nibble + 'A'. Known vector:
    # 'F' = 0x46 -> 'E','G'; space 0x20 -> 'C','A'; suffix 0x00 -> 'A','A'.
    enc = nbt_encode("FRED")
    check(len(enc) == 32, "16 name bytes → 32 encoded bytes")
    check(enc[:2] == b"EG", "'F' (0x46) encodes to 'EG'")
    check(enc[-2:] == b"AA", "the 0x00 workstation suffix encodes to 'AA'")
    check(nbt_encode("fred")[:2] == b"EG", "name is upper-cased before encoding")


def test_build_nbtns_query_is_wellformed():
    q = build_nbtns_query("zzdecoy", 0x0202)
    rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", q[:12])
    check(rid == 0x0202, "txid encoded")
    check(flags == 0x0110 and qd == 1, "broadcast+RD query, one question")
    check(q[12] == 0x20, "question opens with the 0x20 length byte")
    check(q[-4:] == struct.pack(">HH", 0x0020, 0x0001), "qtype NB / qclass IN")


def test_probe_is_empty_on_an_honest_lan():
    check(probe(transport=_Silent(), name="zzdecoy") == [], "no reply → no responder")


def test_probe_ignores_a_mismatched_id():
    check(probe(transport=_WrongId(), name="zzdecoy") == [],
          "a reply with the wrong txid is not counted (stray traffic)")


# --- assessment -----------------------------------------------------------

def test_any_responder_is_one_critical_finding():
    rs = [Responder("10.0.0.66", "LLMNR", "zz"), Responder("10.0.0.66", "mDNS", "zz.local")]
    f = assess(rs, "zz", "host")
    check(len(f) == 1, "collapsed to one finding for the IP")
    check(f[0].severity == "critical", "poisoning is critical")
    check(f[0].source_module == "lan-poison", "tagged to its module")
    check("10.0.0.66" in f[0].message, "names the responder")
    check(assess([], "zz", "host") == [], "no responder → no finding")


# --- the skill: honest states --------------------------------------------

def test_skill_render_states():
    not_checked = namewatch._render([], "host", probed=False)
    check("NOT a clean bill" in not_checked, "unprobed → explicit not-checked")
    quiet = namewatch._render([], "host", probed=True)
    check("No responder answered" in quiet and "not a guarantee" in quiet,
          "quiet probe is honest, not an all-clear")
    hit = namewatch._render(assess([Responder("10.0.0.66", "LLMNR", "zz")], "zz", "host"),
                            "host", probed=True)
    check("[critical]" in hit, "a responder renders as critical")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    print(f"{passed} tests passed")
