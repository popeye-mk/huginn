"""Bundled-data resolution, frozen and unfrozen (spec §20).

The failure mode being guarded here is specific and nasty: if the
knowledge base does not ship with the binary, the rule set loads empty,
no rules match, and the report says "no problems found". A packaging
mistake would be indistinguishable from a healthy machine — the exact
inversion of §3.4 that the whole tool is built to avoid.
"""

import os

import pytest

import resources


def test_source_layout_resolves_to_the_repo():
    assert os.path.isdir(resources.resource_path("pattern_kb"))
    assert os.path.isfile(resources.resource_path("pattern_kb", "entries.yaml"))


def test_all_required_data_files_exist_in_source():
    assert resources.missing_data_files() == []


def test_frozen_layout_uses_the_extraction_directory(monkeypatch, tmp_path):
    """PyInstaller unpacks to _MEIPASS; __file__ points inside the archive."""
    monkeypatch.setattr(resources.sys, "frozen", True, raising=False)
    monkeypatch.setattr(resources.sys, "_MEIPASS", str(tmp_path), raising=False)

    assert resources.is_frozen() is True
    assert resources.base_path() == str(tmp_path)
    assert resources.resource_path("pattern_kb", "entries.yaml").startswith(str(tmp_path))


def test_missing_data_is_detected_not_silently_tolerated(monkeypatch, tmp_path):
    monkeypatch.setattr(resources.sys, "_MEIPASS", str(tmp_path), raising=False)
    assert set(resources.missing_data_files()) == set(resources.REQUIRED_DATA_FILES)


def test_startup_refuses_to_run_without_a_knowledge_base(monkeypatch, tmp_path):
    """An empty rule set reports every machine as healthy. Refuse instead."""
    monkeypatch.setattr(resources.sys, "_MEIPASS", str(tmp_path), raising=False)

    with pytest.raises(SystemExit) as excinfo:
        resources.assert_data_files_present()

    message = str(excinfo.value)
    assert "packaging fault" in message
    assert "healthy" in message, "the error must explain why running anyway is unsafe"


def test_startup_check_passes_in_a_normal_checkout():
    resources.assert_data_files_present()


def test_required_files_cover_every_loader():
    """A new KB file must be added here, or it silently won't ship."""
    import decoder
    import interpreter
    import policy
    import triage

    loaded_paths = {
        interpreter.KB_PATH, interpreter.CHAINS_PATH,
        triage.TRIAGE_PATH, decoder.CODES_PATH, policy.DEFAULT_POLICY,
    }
    declared = {resources.resource_path(rel) for rel in resources.REQUIRED_DATA_FILES}

    missing = loaded_paths - declared
    assert not missing, f"loaded at runtime but not declared for packaging: {missing}"
