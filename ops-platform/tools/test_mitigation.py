"""Tests for mitigation advice (G6) — and the safety guarantee.

Two jobs: pin that each confirmed finding maps to the right explained,
copy-pasteable fix; and — the important one — assert by inspecting the
source that this module imports NO execution primitive (subprocess, socket,
os.system, ...). That is the machine-checkable form of "recommends, never
acts": the code structurally cannot block traffic even if asked.

Run: python3 tools/test_mitigation.py
"""

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts.finding import Coverage, Finding  # noqa: E402
from domains.mitigation import mitigation_for, mitigations_for  # noqa: E402


def _f(fid):
    return Finding(
        id=fid, source_module="lan-exposure", machine_id="host",
        severity="critical", confidence="certain", message="m",
        coverage=Coverage(checked=1, total=1), tags=("security",))


def test_telnet_exposure_gets_a_close_command():
    m = mitigation_for(_f("exposure_192.168.1.5_23"))
    assert m is not None
    assert "Telnet" in m.title and "192.168.1.5" in m.title
    assert "23" in m.command                       # a concrete, runnable fix
    assert m.why and m.steps                        # explained


def test_ftp_mentions_the_fritzbox_nas_path():
    m = mitigation_for(_f("exposure_192.168.1.1_21"))
    assert "FTP" in m.title
    assert "Fritz" in m.steps or "SFTP" in m.steps


def test_http_admin_is_ui_only_no_blind_command():
    m = mitigation_for(_f("exposure_192.168.1.1_80"))
    assert m.command == ""                          # don't blindly block a device UI
    assert "ack" in m.steps.lower()                 # offers the accept path


def test_rogue_dhcp_mitigation_is_locate_and_disconnect():
    m = mitigation_for(_f("rogue_dhcp_192.168.1.99"))
    assert "rogue DHCP" in m.title
    assert "disconnect" in m.steps.lower()


def test_arp_spoof_mitigation():
    m = mitigation_for(_f("arp_dup_ip_192.168.1.1"))
    assert "ARP" in m.title or "impersonat" in m.why.lower()


def test_new_device_mitigation_offers_block_path():
    m = mitigation_for(_f("lan_new_device_de:ad:be:ef:00:01"))
    assert "de:ad:be:ef:00:01" in m.title
    assert "block" in m.steps.lower() or "Fritz" in m.steps


def test_unknown_finding_yields_no_mitigation():
    assert mitigation_for(_f("some_other_finding_x")) is None


def test_mitigations_for_collects_and_skips_unknown():
    findings = [_f("exposure_1_23"), _f("unknown_x"), _f("rogue_dhcp_2")]
    ms = mitigations_for(findings)
    assert len(ms) == 2                             # telnet + rogue dhcp, not unknown


def test_module_imports_no_execution_primitive():
    """The safety line, machine-checked: no way to act on the network."""
    src = (ROOT / "domains" / "mitigation" / "service.py").read_text()
    tree = ast.parse(src)
    banned = {"subprocess", "socket", "os", "pty", "shutil", "requests",
              "urllib", "http", "asyncio"}
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    leaks = imported & banned
    assert not leaks, f"mitigation must not import execution primitives: {leaks}"

    # No dangerous *calls* either (check the AST, not prose — the docstring
    # legitimately mentions 'subprocess' when explaining what it won't do).
    banned_calls = {"eval", "exec", "system", "popen", "Popen", "call",
                    "run", "check_output", "spawn"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            assert name not in banned_calls, f"forbidden call: {name}"


# --- G13: the flood findings get a fix -------------------------------------

def test_flood_findings_get_a_containment_fix():
    for fid in ("arp_flood_churn", "mac_flood_burst"):
        m = mitigation_for(_f(fid))
        assert m is not None, fid + " must map to a fix"
        assert "Contain the flood" in m.title
        assert "isconnect" in m.steps, "the fix says to disconnect the uplink"
        assert "not captured" in m.why, "stays honest: the packets were not seen"


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed} tests passed")
