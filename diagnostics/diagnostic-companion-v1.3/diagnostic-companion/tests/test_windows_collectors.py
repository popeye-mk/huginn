"""Windows collectors can't be exercised against a real Windows box in
this environment (see Diagnostic_Companion_Next_Steps.md). Two things
are still tested from Linux:

1. parse() functions against realistic canned PowerShell JSON output —
   checks the parsing logic independently of whether the live
   subprocess call is right.
2. collect() degrades to a clean Skip (not a crash) when PowerShell
   simply isn't present, which is exactly what happens by construction
   on this Linux sandbox and proves the graceful-degradation path
   works even for a platform's collectors that can't fully run here.
"""

import json
import shutil

import pytest

from collectors.base import Skip
from collectors.windows import _powershell
from collectors.windows import disk as win_disk
from collectors.windows import logs as win_logs
from collectors.windows import network as win_network
from collectors.windows import system as win_system


def test_system_parse():
    raw = '{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631","FreePhysicalMemory":4194304,"TotalVisibleMemorySize":16777216}'
    data = win_system.parse(raw)
    assert data["os_release"] == "Microsoft Windows 11 Pro"
    assert data["mem_total_mb"] == 16384.0
    assert data["mem_available_mb"] == 4096.0
    assert data["mem_used_percent"] == 75.0


def test_disk_parse_single_volume_not_wrapped_in_list():
    # PowerShell's ConvertTo-Json collapses a single-item pipeline result
    # to a bare object rather than a one-element array — parse() must
    # handle both shapes.
    raw = '{"DeviceID":"C:","Size":256060514304,"FreeSpace":10737418240,"FileSystem":"NTFS"}'
    data = win_disk.parse(raw)
    assert len(data["volumes"]) == 1
    assert data["volumes"][0]["device"] == "C:"
    assert data["min_free_percent"] == pytest.approx(4.2, abs=0.1)


def test_disk_parse_multiple_volumes():
    raw = (
        '[{"DeviceID":"C:","Size":256060514304,"FreeSpace":128030257152,"FileSystem":"NTFS"},'
        '{"DeviceID":"D:","Size":1000000000000,"FreeSpace":900000000000,"FileSystem":"NTFS"}]'
    )
    data = win_disk.parse(raw)
    assert len(data["volumes"]) == 2
    assert data["min_free_percent"] == 50.0


def test_network_parse():
    raw = (
        '{"Interface":"Ethernet","Gateway":"192.168.1.1",'
        '"DnsServers":["192.168.1.1"],'
        '"DnsResults":{"example.com":true,"cloudflare.com":true,"wikipedia.org":false},'
        '"GatewayReachable":true,"PublicReachable":true}'
    )
    data = win_network.parse(raw)
    assert data["gateway"] == "192.168.1.1"
    assert data["dns_any_failed"] is True
    assert data["gateway_ping"]["reachable"] is True


def test_logs_parse_empty_is_healthy_not_an_error():
    data = win_logs.parse('{"ErrorCount":0,"WindowHours":24,"Entries":[]}')
    assert data["error_count"] == 0
    assert data["entries"] == []


def test_logs_parse_tolerates_the_older_bare_array_shape():
    """Golden captures from an earlier build must still parse."""
    data = win_logs.parse("[]")
    assert data["error_count"] == 0
    assert data["entries"] == []


def test_logs_parse_entries():
    raw = json.dumps({
        "ErrorCount": 1,
        "WindowHours": 24,
        "Entries": [{
            "TimeCreated": "/Date(1753000000000)/", "Id": 41,
            "LevelDisplayName": "Critical", "ProviderName": "Kernel-Power",
            "Message": "The system rebooted without cleanly shutting down first.",
        }],
    })
    data = win_logs.parse(raw)
    assert data["error_count"] == 1
    assert "Kernel-Power" in data["entries"][0]


def test_logs_parse_handles_a_single_entry_collapsed_to_an_object():
    """ConvertTo-Json turns a one-element array into a bare object."""
    raw = json.dumps({
        "ErrorCount": 1, "WindowHours": 24,
        "Entries": {"TimeCreated": "t", "Id": 41, "LevelDisplayName": "Error",
                    "ProviderName": "Kernel-Power", "Message": "m"},
    })
    data = win_logs.parse(raw)
    assert data["error_count"] == 1
    assert len(data["entries"]) == 1


def test_non_english_log_message_survives_parsing():
    """Event log text on a localised Windows is not ASCII (spec §19)."""
    raw = json.dumps({
        "ErrorCount": 2, "WindowHours": 24,
        "Entries": [{"TimeCreated": "t", "Id": 7000, "LevelDisplayName": "Fout",
                     "ProviderName": "Serviceborteler",
                     "Message": "De service kon niet worden gestart — hé"}],
    }, ensure_ascii=False)
    data = win_logs.parse(raw)
    assert "hé" in data["entries"][0]


@pytest.mark.parametrize("module", [win_system, win_disk, win_network, win_logs])
def test_collect_skips_cleanly_without_powershell(module, monkeypatch):
    """A machine with no PowerShell must Skip, never crash (§3.4/§3.7).

    This originally asserted the behaviour unconditionally, which only
    worked because the build environment happened to be a Linux box with
    no PowerShell installed. On a real Windows machine PowerShell *is*
    present, collect() correctly ran, and the test failed — reporting a
    fact about the environment as though it were a bug in the code.

    The absent-PowerShell condition is now simulated rather than
    assumed, so the degradation path is exercised on every platform
    instead of only the one where it happens to be true.
    """
    monkeypatch.setattr(_powershell.shutil, "which", lambda _name: None)
    with pytest.raises(Skip):
        module.collect()


@pytest.mark.skipif(
    not (shutil.which("pwsh") or shutil.which("powershell")),
    reason="no PowerShell on this machine — nothing to run against",
)
@pytest.mark.parametrize("module", [win_system, win_disk, win_network, win_logs])
def test_collect_returns_data_on_a_real_windows_machine(module):
    """The complement: where PowerShell exists, collect() returns a dict.

    Skipped on Linux CI, meaningful on Windows. A collector that raises
    here is a real bug rather than an environment artefact.
    """
    data = module.collect()
    assert isinstance(data, dict)
    assert data, "collector returned an empty dict"


def test_windows_error_count_is_not_capped_by_the_entry_sample():
    """A count that saturates at the sample size makes cross-platform
    rules silently unfireable — `severe_error_log_volume` fires above
    100 and could never reach it while error_count was len(entries)."""
    from collectors.windows import logs

    raw = json.dumps({
        "ErrorCount": 347,
        "WindowHours": 24,
        "Entries": [
            {"TimeCreated": "2026-07-20T09:00:00", "Id": 7000,
             "LevelDisplayName": "Error", "ProviderName": "Service Control Manager",
             "Message": "A service failed to start."}
        ],
    })
    parsed = logs.parse(raw)

    assert parsed["error_count"] == 347
    assert parsed["error_count"] > len(parsed["entries"])
    assert len(parsed["entries"]) == 1


def test_windows_log_entries_are_capped_but_count_is_not():
    from collectors.windows import logs

    raw = json.dumps({
        "ErrorCount": 500,
        "WindowHours": 24,
        "Entries": [
            {"TimeCreated": f"t{i}", "Id": i, "LevelDisplayName": "Error",
             "ProviderName": "P", "Message": "m"} for i in range(50)
        ],
    })
    parsed = logs.parse(raw)

    assert parsed["error_count"] == 500
    assert len(parsed["entries"]) == logs.MAX_ENTRIES


def test_windows_empty_log_is_zero_not_an_error():
    """Get-WinEvent throws when nothing matches; a quiet machine is healthy."""
    from collectors.windows import logs

    parsed = logs.parse('{"ErrorCount":0,"WindowHours":24,"Entries":[]}')
    assert parsed["error_count"] == 0
    assert parsed["entries"] == []
