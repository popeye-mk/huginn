"""Tests for the fleet view (R6).

The tests that matter here are about what the fleet view refuses to
claim. A dashboard's failure mode is not crashing — it is showing a
comforting number that isn't true, and a solo admin trusting one green
screen is exactly the person this platform is for.

So: an unchecked machine is never healthy, a score never appears without
its coverage, and correlation keeps its denominator.

Run: python3 tools/test_devices.py
"""

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from contracts import Device, DeviceHealth  # noqa: E402
from domains.devices import DeviceRepository, DeviceService  # noqa: E402


_SKIPPED = []


def _fleet_unavailable(view) -> bool:
    """Whether Diagnostic Companion's fleet module could be imported.

    `fleet.py` imports its siblings, which import PyYAML. On a machine
    without it, correlation legitimately yields nothing — and asserting
    a denominator against that produced a bare `assert 2 == 0` on the
    first Windows run, which blamed the fleet view for a missing
    dependency. The view already reports this; the test now reads it.
    """
    if not view.fleet_available:
        print(f"      SKIP: fleet correlation unavailable — {view.unavailable_reason}")
        _SKIPPED.append(f"fleet correlation ({view.unavailable_reason})")
        return True
    return False


def _repo() -> DeviceRepository:
    return DeviceRepository(Path(tempfile.mkdtemp()) / "devices.db")


def _snapshot(host="web-02", **sections):
    return {
        "schema_version": "0.1.0",
        "hostname": host,
        "os": "linux",
        "sections": sections or {
            "disk": {"status": "ok", "reason": None, "data": {"min_free_percent": 4.0}}
        },
    }


# --- persistence ----------------------------------------------------------

def test_a_device_is_stored_and_read_back():
    repo = _repo()
    repo.upsert(Device(device_id="web-02", hostname="web-02", os_family="linux"))

    devices = repo.all_devices()
    assert len(devices) == 1
    assert devices[0].hostname == "web-02"


def test_rescanning_updates_rather_than_duplicates():
    repo = _repo()
    for _ in range(3):
        repo.upsert(Device(device_id="web-02", hostname="web-02"))
    assert repo.count() == 1


def test_first_seen_survives_a_rescan():
    """When a machine was first seen is history; it must not be overwritten."""
    repo = _repo()
    repo.upsert(Device(device_id="web-02", hostname="web-02",
                       first_seen="2020-01-01T00:00:00+00:00"))
    repo.upsert(Device(device_id="web-02", hostname="web-02"))

    assert repo.all_devices()[0].first_seen.startswith("2020-01-01")


def test_health_is_stored_with_its_coverage():
    """A score and the coverage it was measured over travel together."""
    repo = _repo()
    repo.upsert(Device(device_id="web-02", hostname="web-02"))
    repo.record_health(DeviceHealth(device_id="web-02", score=42, checked=4, total=7))

    health = repo.health_for("web-02")
    assert health.score == 42
    assert health.coverage_label == "4/7 checked"
    assert health.is_trustworthy is False


def test_snapshots_are_files_and_the_row_points_at_them():
    repo = _repo()
    repo.upsert(Device(device_id="web-02", hostname="web-02"))
    path = repo.save_snapshot("web-02", _snapshot())

    assert path.exists()
    assert path in repo.snapshot_paths("web-02")


def test_snapshot_history_is_pruned_to_the_keep_limit():
    """Every 3h forever would grow without bound; keep only the newest N.

    Timestamp filenames sort chronologically, so pruning drops the oldest.
    The newest are the ones kept, and the count never exceeds the limit."""
    repo = DeviceRepository(Path(tempfile.mkdtemp()) / "devices.db", snapshot_keep=3)
    directory = repo.snapshot_dir / "web-02"
    directory.mkdir(parents=True, exist_ok=True)
    stamps = ["20260101T000000Z", "20260101T030000Z", "20260101T060000Z",
              "20260101T090000Z", "20260101T120000Z"]
    for s in stamps:
        (directory / f"{s}.json").write_text("{}", encoding="utf-8")

    removed = repo._prune_snapshots("web-02")

    kept = sorted(p.name for p in repo.snapshot_paths("web-02"))
    assert removed == 2
    assert kept == ["20260101T060000Z.json", "20260101T090000Z.json",
                    "20260101T120000Z.json"]           # the 3 newest


def test_saving_a_snapshot_keeps_history_bounded():
    """The save path itself prunes — no separate cleanup job to remember."""
    repo = DeviceRepository(Path(tempfile.mkdtemp()) / "devices.db", snapshot_keep=2)
    repo.upsert(Device(device_id="web-02", hostname="web-02"))
    directory = repo.snapshot_dir / "web-02"
    directory.mkdir(parents=True, exist_ok=True)
    for s in ["20250101T000000Z", "20250101T030000Z", "20250101T060000Z"]:
        (directory / f"{s}.json").write_text("{}", encoding="utf-8")  # old backlog

    newest = repo.save_snapshot("web-02", _snapshot())   # triggers the prune

    paths = repo.snapshot_paths("web-02")
    assert len(paths) == 2                       # bounded to the keep limit
    assert newest == paths[-1]                   # the just-written one survived


# --- what the fleet view refuses to claim ---------------------------------

def test_an_unchecked_machine_is_never_reported_as_healthy():
    """The rule that matters. Unknown is not fine."""
    service = DeviceService(_repo())
    service.repository.upsert(Device(device_id="db-01", hostname="db-01"))

    view = service.fleet()
    assert view.total == 1
    assert [d.hostname for d in view.unassessed] == ["db-01"]
    assert "db-01" not in view.health


def test_partial_coverage_is_flagged_as_untrustworthy():
    service = DeviceService(_repo())
    service.repository.upsert(Device(device_id="web-02", hostname="web-02"))
    service.repository.record_health(
        DeviceHealth(device_id="web-02", score=100, checked=3, total=9)
    )

    view = service.fleet()
    assert [h.device_id for h in view.untrustworthy] == ["web-02"]


def test_full_coverage_is_not_flagged():
    service = DeviceService(_repo())
    service.repository.upsert(Device(device_id="web-02", hostname="web-02"))
    service.repository.record_health(
        DeviceHealth(device_id="web-02", score=67, checked=4, total=4)
    )
    assert service.fleet().untrustworthy == []


def test_recording_the_wrong_snapshot_shape_fails_loudly():
    """`fleet.load_snapshots` skips anything without `sections` in silence.

    Passing the engine's outer payload produced an empty fleet view and no
    error at all — found exactly that way. Now it raises.
    """
    service = DeviceService(_repo())
    try:
        service.record_scan("web-02", "linux", {"snapshot": {"sections": {}}})
    except ValueError as exc:
        assert "sections" in str(exc)
        return
    raise AssertionError("the outer payload should have been rejected")


def test_record_scan_stores_device_snapshot_and_health():
    service = DeviceService(_repo())
    service.record_scan(
        "web-02", "linux", _snapshot(),
        {"score": 67, "checked": 4, "total": 4},
    )

    view = service.fleet()
    assert view.total == 1
    assert view.health["web-02"].score == 67
    if _fleet_unavailable(view):
        return
    assert view.snapshots_read == 1


def test_correlation_keeps_its_denominator():
    """"3 affected" without "of 5 checked" is not an actionable number."""
    service = DeviceService(_repo())
    for host in ("web-02", "web-03"):
        service.record_scan(
            host, "linux", _snapshot(host),
            {"score": 67, "checked": 1, "total": 1},
        )

    view = service.fleet()
    if _fleet_unavailable(view):
        return
    assert view.snapshots_read == 2
    for finding in view.shared_findings:
        assert "affected" in finding
        assert "checked" in finding


def test_an_empty_fleet_reports_nothing_rather_than_zero_health():
    view = DeviceService(_repo()).fleet()
    assert view.total == 0
    assert view.shared_findings == []
    assert view.snapshots_read == 0


def test_correlation_failure_is_reported_not_raised():
    """A broken fleet module must not take the device list down with it."""
    service = DeviceService(_repo())
    service.record_scan("web-02", "linux", _snapshot())
    service._load_fleet_module = lambda: None

    view = service.fleet()
    assert view.total == 1
    assert view.fleet_available is False
    assert view.unavailable_reason


if __name__ == "__main__":
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  ok  {name}")
            passed += 1
    print(f"\n{passed - len(_SKIPPED)} tests passed, {len(_SKIPPED)} skipped")
    for skipped in _SKIPPED:
        print(f"  skipped (UNVERIFIED): {skipped}")
