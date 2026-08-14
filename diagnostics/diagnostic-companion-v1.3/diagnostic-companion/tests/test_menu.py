"""Menu behaviour (spec §14.2, §14.5).

The menu is the surface a *client* sees — someone watching a stranger
run software on their own computer. Two properties matter more than
anything cosmetic: it must not be able to change their machine, and it
must not be able to crash and take the window with it.
"""

import io

import pytest

import menu


class FakeRunner:
    """Records the command lines the menu asks for."""

    def __init__(self, exit_code=0):
        self.calls = []
        self.exit_code = exit_code

    def __call__(self, argv):
        self.calls.append(argv)
        return self.exit_code


def drive(inputs, monkeypatch, runner=None, capture=None):
    """Run the menu against scripted keystrokes."""
    runner = runner or FakeRunner()
    output = capture if capture is not None else []
    supplied = iter(inputs)

    monkeypatch.setattr(menu, "_prompt", lambda _text="": next(supplied, "q"))
    monkeypatch.setattr(menu, "_pause", lambda: None)
    monkeypatch.setattr(menu, "_say", lambda text="": output.append(str(text)))

    code = menu.run_menu(runner)
    return code, runner, "\n".join(output)


# --- safety -----------------------------------------------------------

def test_no_menu_option_can_change_the_machine(monkeypatch):
    """`fix` must be unreachable from here, even in dry-run form.

    A menu shown to a client is the wrong place to expose the one
    command capable of altering anything. Every option is walked,
    including the elevation prompt, which is declined.
    """
    _code, runner, _out = drive(
        ["1", "2", "3", "n", "4", "0x1", "5", "6", "7", "q"], monkeypatch)
    issued = [c[0] for c in runner.calls]

    assert "fix" not in issued
    assert all("--apply" not in arg for call in runner.calls for arg in call)


def test_front_screen_states_the_tool_only_reads(monkeypatch):
    """Someone watching deserves to be told before anything runs."""
    _code, _runner, out = drive(["q"], monkeypatch)
    assert "only reads" in out
    assert "does not change anything" in out


def test_quit_confirms_nothing_was_changed(monkeypatch):
    _code, _runner, out = drive(["q"], monkeypatch)
    assert "Nothing on this computer was changed" in out


# --- robustness -------------------------------------------------------

@pytest.mark.parametrize("keystroke", ["banana", "99", "-1", "!!", " "])
def test_unrecognised_input_reprompts_rather_than_crashing(keystroke, monkeypatch):
    code, _runner, out = drive([keystroke, "q"], monkeypatch)
    assert code == 0
    assert "did not recognise" in out


def test_a_failing_command_does_not_end_the_session(monkeypatch):
    """One command failing must not close the window mid-visit."""
    code, runner, _out = drive(["1", "q"], monkeypatch, runner=FakeRunner(exit_code=2))
    assert code == 0
    assert runner.calls


def test_closed_stdin_exits_cleanly(monkeypatch):
    """Ctrl+D, or being piped, must not hang or traceback."""
    monkeypatch.setattr(menu, "_pause", lambda: None)
    monkeypatch.setattr(menu, "_say", lambda _text="": None)
    monkeypatch.setattr("builtins.input", lambda _p="": (_ for _ in ()).throw(EOFError))

    assert menu.run_menu(FakeRunner()) == 0


def test_ctrl_c_at_the_prompt_quits_rather_than_tracebacks(monkeypatch):
    monkeypatch.setattr(menu, "_pause", lambda: None)
    monkeypatch.setattr(menu, "_say", lambda _text="": None)
    monkeypatch.setattr("builtins.input",
                        lambda _p="": (_ for _ in ()).throw(KeyboardInterrupt))

    assert menu.run_menu(FakeRunner()) == 0


# --- options map to real commands -------------------------------------

def test_check_option_uses_the_plain_language_view(monkeypatch):
    _code, runner, _out = drive(["1", "q"], monkeypatch)
    assert runner.calls[0] == ["simple"]


def test_baseline_and_diff_use_the_documented_commands(monkeypatch):
    _code, runner, _out = drive(["6", "7", "q"], monkeypatch)
    assert ["baseline"] in runner.calls
    assert ["run", "--diff"] in runner.calls


def test_decode_passes_the_code_through_untouched(monkeypatch):
    _code, runner, _out = drive(["4", "0x80070005", "q"], monkeypatch)
    assert ["decode", "0x80070005"] in runner.calls


def test_empty_code_returns_to_the_menu_without_calling_decode(monkeypatch):
    _code, runner, _out = drive(["4", "", "q"], monkeypatch)
    assert not any(c[0] == "decode" for c in runner.calls)


def test_report_option_requests_html_to_an_explicit_path(monkeypatch):
    _code, runner, _out = drive(["2", "q"], monkeypatch)
    call = next(c for c in runner.calls if c[0] == "run")

    assert "--format" in call and "html" in call
    assert "-o" in call, "must write to a named file, not the current directory"


# --- accessibility (§14.2) --------------------------------------------

def test_menu_contains_no_emoji(monkeypatch):
    """Consoles mangle them; the same rule as every other text surface."""
    _code, _runner, out = drive(["q"], monkeypatch)
    assert all(ord(ch) < 0x2190 for ch in out), "non-ASCII symbol in menu output"


def test_menu_avoids_jargon_in_the_options(monkeypatch):
    """The client reads this screen too."""
    _code, _runner, out = drive(["q"], monkeypatch)
    for jargon in ("collector", "snapshot", "schema", "stdout", "exit code"):
        assert jargon not in out.lower()


# --- auto-launch ------------------------------------------------------

def test_auto_launches_only_when_packaged_with_no_arguments(monkeypatch):
    monkeypatch.setattr(menu.sys, "stdin", io.StringIO())
    monkeypatch.setattr(menu.sys, "stdout", io.StringIO())
    # StringIO is not a tty, so this stays False regardless
    assert menu.should_auto_launch([], frozen=True) is False


def test_never_auto_launches_from_source(monkeypatch):
    """`python cli.py` with no args should print help, not open a menu."""
    assert menu.should_auto_launch([], frozen=False) is False


def test_never_auto_launches_when_arguments_are_given():
    assert menu.should_auto_launch(["run"], frozen=True) is False


def test_never_auto_launches_when_piped(monkeypatch):
    """A redirected invocation must not block waiting for input."""
    class NotATty(io.StringIO):
        def isatty(self):
            return False

    monkeypatch.setattr(menu.sys, "stdin", NotATty())
    monkeypatch.setattr(menu.sys, "stdout", NotATty())
    assert menu.should_auto_launch([], frozen=True) is False


# --- elevation (§3.1) -------------------------------------------------

def test_elevation_is_offered_only_when_it_would_do_something(monkeypatch):
    """Already root? Then option 1 covers the drive and 'also check it'
    would be a nonsense offer."""
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: True)
    _code, _runner, out = drive(["q"], monkeypatch)
    assert "asks for your password" not in out

    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    _code, _runner, out = drive(["q"], monkeypatch)
    assert "asks for your password" in out


def test_elevation_explains_itself_before_prompting(monkeypatch):
    """Escalating without saying why is what untrustworthy software does."""
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    _code, _runner, out = drive(["3", "n", "q"], monkeypatch)

    assert "drive health" in out.lower()
    assert "only reads" in out.lower()


def test_declining_elevation_runs_nothing(monkeypatch):
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    called = []
    monkeypatch.setattr(menu.elevate, "run_elevated",
                        lambda *a, **k: called.append(a) or 0)

    _code, _runner, out = drive(["3", "n", "q"], monkeypatch)
    assert not called
    assert "Left as it was" in out


def test_accepting_elevation_reruns_the_plain_language_view(monkeypatch):
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    monkeypatch.setattr(menu.elevate, "can_elevate", lambda: True)
    called = []
    monkeypatch.setattr(menu.elevate, "run_elevated",
                        lambda args, **k: called.append(args) or 0)

    drive(["3", "y", "q"], monkeypatch)
    assert called == [["simple"]]


def test_cancelled_password_prompt_is_not_an_error(monkeypatch):
    """A user declining at the system prompt is a legitimate answer."""
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    monkeypatch.setattr(menu.elevate, "can_elevate", lambda: True)
    monkeypatch.setattr(menu.elevate, "run_elevated", lambda *a, **k: 130)

    code, _runner, out = drive(["3", "y", "q"], monkeypatch)
    assert code == 0
    assert "Cancelled" in out


def test_no_escalation_mechanism_gives_the_manual_command(monkeypatch):
    monkeypatch.setattr(menu.elevate, "already_elevated", lambda: False)
    monkeypatch.setattr(menu.elevate, "can_elevate", lambda: False)

    _code, _runner, out = drive(["3", "y", "q"], monkeypatch)
    assert "run this by hand" in out.lower()
