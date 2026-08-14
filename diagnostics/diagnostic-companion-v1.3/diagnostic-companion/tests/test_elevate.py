"""Privilege escalation (spec §3.1, §3.2).

The tool is read-only by contract. Elevation exists solely so the drive
can be asked about its own health, and the properties worth protecting
are about restraint rather than capability: it must never escalate
without being asked, never claim it can when it cannot, and never treat
a declined password prompt as a failure.
"""

import os
import sys

import pytest

import elevate


def test_own_command_points_at_this_program_from_source():
    command = elevate._own_command()
    assert command[0] == sys.executable
    assert command[1].endswith("cli.py")


def test_frozen_invokes_the_executable_directly(monkeypatch, tmp_path):
    exe = tmp_path / "diag"
    exe.write_text("", encoding="utf-8")
    monkeypatch.setattr(elevate.resources, "is_frozen", lambda: True)
    monkeypatch.setattr(sys, "executable", str(exe))

    assert elevate._own_command() == [str(exe)]


def test_uses_the_current_interpreter_not_a_bare_python(monkeypatch):
    """A venv install must not escalate into the system interpreter.

    `sudo python3 cli.py` would run an interpreter that may not have
    pyyaml installed, failing in a way that looks like a tool bug.
    """
    command = elevate._own_command()
    assert command[0] != "python3"
    assert os.path.isabs(command[0])


def test_graphical_prompt_is_preferred_on_linux(monkeypatch):
    """Launched from a desktop icon there may be no terminal to type into,
    so pkexec (graphical) is preferred over sudo."""
    monkeypatch.setattr(elevate.shutil, "which",
                        lambda tool: f"/usr/bin/{tool}")
    assert elevate.linux_escalator().endswith("pkexec")


def test_falls_back_to_sudo(monkeypatch):
    monkeypatch.setattr(elevate.shutil, "which",
                        lambda tool: "/usr/bin/sudo" if tool == "sudo" else None)
    assert elevate.linux_escalator().endswith("sudo")


def test_can_elevate_is_false_when_nothing_is_available(monkeypatch):
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _tool: None)
    assert elevate.can_elevate() is False


def test_missing_mechanism_raises_rather_than_failing_quietly(monkeypatch):
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _tool: None)

    with pytest.raises(elevate.ElevationUnavailable):
        elevate.run_elevated(["simple"])


def test_explanation_states_that_nothing_is_changed(monkeypatch):
    """§3.2 — the read-only guarantee still holds when elevated."""
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _t: "/usr/bin/pkexec")

    text = elevate.explain()
    assert "nothing is changed" in text.lower()
    assert "password" in text.lower()


def test_windows_explanation_mentions_the_uac_prompt(monkeypatch):
    monkeypatch.setattr(elevate, "is_windows", lambda: True)
    text = elevate.explain()
    assert "User Account Control" in text
    assert "nothing is changed" in text.lower()


def test_manual_hint_is_runnable_as_written(monkeypatch):
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    hint = elevate.manual_command_hint(["run"])
    assert hint.strip().startswith("sudo ")
    assert hint.strip().endswith("run")


def test_windows_manual_hint_does_not_suggest_sudo(monkeypatch):
    monkeypatch.setattr(elevate, "is_windows", lambda: True)
    hint = elevate.manual_command_hint(["run"])
    assert "sudo" not in hint
    assert "Administrator" in hint


def test_interrupted_escalation_reports_cancellation(monkeypatch):
    """Ctrl+C at a password prompt is a decision, not a crash."""
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _t: "/usr/bin/sudo")
    monkeypatch.setattr(elevate.subprocess, "call",
                        lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt))

    assert elevate.run_elevated(["simple"]) == 130


def test_timeout_is_reported_distinctly(monkeypatch):
    import subprocess as sp
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _t: "/usr/bin/sudo")
    monkeypatch.setattr(elevate.subprocess, "call",
                        lambda *a, **k: (_ for _ in ()).throw(
                            sp.TimeoutExpired("x", 1)))

    assert elevate.run_elevated(["simple"]) == 124


def test_escalated_command_carries_the_requested_arguments(monkeypatch):
    seen = {}
    monkeypatch.setattr(elevate, "is_windows", lambda: False)
    monkeypatch.setattr(elevate.shutil, "which", lambda _t: "/usr/bin/sudo")
    monkeypatch.setattr(elevate.subprocess, "call",
                        lambda cmd, **k: seen.update(cmd=cmd) or 0)

    elevate.run_elevated(["simple"])
    assert seen["cmd"][0] == "/usr/bin/sudo"
    assert seen["cmd"][-1] == "simple"


def test_no_write_command_is_reachable_through_elevation():
    """Elevation grants read access to disk counters, nothing more.

    If `fix` ever became reachable from an elevated path it would break
    the read-only guarantee at the one moment it matters most.
    """
    import inspect
    source = inspect.getsource(elevate)
    assert "fix" not in source.replace("prefix", "").replace("suffix", "")
