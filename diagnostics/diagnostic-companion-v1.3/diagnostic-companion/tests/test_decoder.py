"""Error-code decoder tests (spec §10)."""

import pytest

import decoder


@pytest.mark.parametrize("form", [
    "0x80070005", "0X80070005", "80070005", " 0x80070005 ", "0x8007_0005",
])
def test_input_forms_all_resolve(form):
    """A code reaches a technician in whatever shape the user typed it."""
    result = decoder.decode(form)
    assert result is not None
    assert result["code"] == "0x80070005"


def test_short_bsod_form_resolves_to_padded_entry():
    """Users type 0x7e; the documented form is 0x0000007E."""
    assert decoder.decode("0x7e")["name"] == "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"
    assert decoder.decode("0x0000007e")["name"] == "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED"


def test_unknown_code_returns_none_not_a_guess():
    """Inventing a meaning for an unknown code is the failure mode here."""
    assert decoder.decode("0xdeadbeef") is None


def test_unknown_render_does_not_imply_harmless():
    text = decoder.render_decode("0xdeadbeef", None)
    assert "not the same as" in text
    assert "harmless" in text


def test_empty_input_is_handled():
    for value in (None, "", "   ", "0x"):
        assert decoder.decode(value) is None


def test_categories_are_labelled_distinctly():
    update = decoder.render_decode("0x80070005", decoder.decode("0x80070005"))
    bsod = decoder.render_decode("0x7e", decoder.decode("0x7e"))
    assert "Windows Update" in update
    assert "Stop code (BSOD)" in bsod


def test_every_entry_has_a_cause_and_next_step():
    """A decoded code with no action is just a longer hex string."""
    codes = decoder.load_codes()
    for category, entries in codes.items():
        for entry in entries:
            assert entry.get("cause"), f"{entry['code']} has no cause"
            assert entry.get("next_step"), f"{entry['code']} has no next_step"


def test_no_duplicate_codes_across_categories():
    seen = set()
    for category, code, _label in decoder.all_codes():
        key = decoder.normalise(code)
        assert key not in seen, f"duplicate code {code}"
        seen.add(key)
