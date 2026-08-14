"""Portable / USB operation (spec §20).

The workflow being protected: a technician carries the binary on a USB
stick, checks several machines in a row, and walks away with one report
per machine. Two ways that quietly fails — reports written somewhere
nobody will find, and each machine overwriting the previous one's file.
"""

import os
import sys
from datetime import datetime

import pytest

import portable


# --- naming -----------------------------------------------------------

def test_report_name_includes_machine_and_time():
    when = datetime(2026, 7, 20, 11, 42)
    assert portable.report_filename("DESKTOP-ABC", "html", when) == \
        "DESKTOP-ABC_2026-07-20_1142.html"


def test_two_machines_never_collide():
    """A fixed filename means machine two silently overwrites machine one."""
    when = datetime(2026, 7, 20, 11, 42)
    assert portable.report_filename("PC-01", "html", when) != \
        portable.report_filename("PC-02", "html", when)


def test_same_machine_checked_twice_does_not_overwrite():
    a = portable.report_filename("PC-01", "html", datetime(2026, 7, 20, 9, 0))
    b = portable.report_filename("PC-01", "html", datetime(2026, 7, 20, 14, 30))
    assert a != b


def test_names_sort_chronologically_per_machine():
    """ISO-ordered so a directory listing is already in time order."""
    names = [portable.report_filename("PC", "html", datetime(2026, 7, 20, h, 0))
             for h in (14, 9, 11)]
    assert sorted(names) == [
        "PC_2026-07-20_0900.html",
        "PC_2026-07-20_1100.html",
        "PC_2026-07-20_1400.html",
    ]


# --- hostile input ----------------------------------------------------

@pytest.mark.parametrize("hostname", [
    "../../etc/passwd",
    "..\\..\\Windows\\System32",
    "name with spaces",
    "name/with/slashes",
    "name:with:colons",
    "",
    None,
])
def test_hostname_cannot_escape_the_output_directory(hostname):
    """The hostname comes off the machine being diagnosed (§13)."""
    name = portable.report_filename(hostname, "html")
    assert "/" not in name and "\\" not in name
    assert not name.startswith(".")
    assert ".." not in name


def test_absurdly_long_hostname_is_truncated():
    name = portable.report_filename("a" * 500, "html")
    assert len(name) < 100


# --- location ---------------------------------------------------------

def test_output_goes_beside_the_program_when_writable(tmp_path, monkeypatch):
    monkeypatch.setattr(portable, "program_dir", lambda: str(tmp_path))
    directory, fell_back = portable.output_dir()

    assert directory == str(tmp_path)
    assert fell_back is False


def test_read_only_stick_falls_back_and_says_so(tmp_path, monkeypatch):
    """A write-protected USB stick must not crash or write silently elsewhere."""
    readonly = tmp_path / "stick"
    readonly.mkdir()
    monkeypatch.setattr(portable, "program_dir", lambda: str(readonly))
    monkeypatch.setattr(portable, "_writable", lambda _p: False)

    directory, fell_back = portable.output_dir()
    assert fell_back is True
    assert directory == os.path.expanduser("~")


def test_frozen_anchors_on_the_executable_not_the_temp_dir(monkeypatch, tmp_path):
    """PyInstaller onefile extracts to a temp dir but sys.executable is the exe.

    Anchoring on the extraction directory would write reports into a
    folder deleted on exit.
    """
    exe = tmp_path / "stick" / "diag.exe"
    exe.parent.mkdir()
    exe.write_text("", encoding="utf-8")

    monkeypatch.setattr(portable, "is_frozen", lambda: True)
    monkeypatch.setattr(sys, "executable", str(exe))
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path / "temp_extract"), raising=False)

    assert portable.program_dir() == str(exe.parent)


def test_report_path_combines_location_and_name(tmp_path, monkeypatch):
    monkeypatch.setattr(portable, "program_dir", lambda: str(tmp_path))
    path, _ = portable.report_path("PC-01", "html", datetime(2026, 7, 20, 11, 42))

    assert os.path.dirname(path) == str(tmp_path)
    assert os.path.basename(path) == "PC-01_2026-07-20_1142.html"


# --- listing ----------------------------------------------------------

def test_existing_reports_lists_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(portable, "program_dir", lambda: str(tmp_path))
    import time

    for name in ("PC-01_2026-07-20_0900.html", "PC-02_2026-07-20_1000.html"):
        (tmp_path / name).write_text("x", encoding="utf-8")
        time.sleep(0.01)

    found = [os.path.basename(p) for p in portable.existing_reports()]
    assert found[0] == "PC-02_2026-07-20_1000.html"


def test_listing_ignores_unrelated_files(tmp_path, monkeypatch):
    monkeypatch.setattr(portable, "program_dir", lambda: str(tmp_path))
    (tmp_path / "diag.exe").write_text("x", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("x", encoding="utf-8")
    (tmp_path / "PC-01_2026-07-20_0900.html").write_text("x", encoding="utf-8")

    found = [os.path.basename(p) for p in portable.existing_reports()]
    assert found == ["PC-01_2026-07-20_0900.html"]


def test_missing_directory_is_not_fatal(monkeypatch):
    monkeypatch.setattr(portable, "program_dir", lambda: "/no/such/place")
    assert portable.existing_reports() == []
