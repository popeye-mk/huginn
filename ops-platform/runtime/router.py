"""Request router — the native shell's dispatch (A3 Phase 4).

One entry point ties the registry (Phase 4) to the grounded answer path
(Phase 3): a line that resolves to a verb runs that skill; anything else is a
question, answered from the operator's notes, then cited web, then an honest
"not found". This is the native replacement for the fork's dispatcher's
command/question split — minus the LLM intent-classification detour, which the
ops verbs do not need.

Every path returns a `CommandResult` (native, Phase 1), and a skill that
raises is reported as a failed command, never propagated — a console tool that
crashes the shell it runs in has made things worse.
"""

from contracts import CommandResult


def dispatch(registry, text, speaker=None):
    """Route one request to an ops verb, or say plainly that it is not one.

    **Huginn answers no general questions** (decided 2026-07-26). She is an
    IT-operations tool: she runs verbs and reports what she found. A tool that
    guesses at questions outside its job trades its one real asset — that when
    it says something, it measured it — for the appearance of being helpful.
    So an unrecognised line gets an honest "not a verb I have" and the list of
    verbs that exist, never an answer assembled from somewhere else.
    """
    verb, args = registry.resolve(text)
    if verb is None:
        return CommandResult(
            False,
            "Not an ops verb. I run diagnostics and watch the LAN; I do not "
            "answer general questions.\nTry: " + ", ".join(registry.names()),
        )
    # Does this machine own the data directory it is about to write to?
    #
    # Checked HERE because this is the one place every verb passes through —
    # `./ops`, the console and the scheduled timers all arrive at dispatch.
    # Enforcing at each write site instead would mean the next store added
    # is the one that gets forgotten.
    #
    # It refuses rather than warns. A warning is read once and scrolled past
    # for a month, and this failure mode is silent by nature: two machines'
    # records are equally well-formed and indistinguishable afterwards.
    from agents.owning import guard
    from platform_support import hostname
    try:
        refused = guard(hostname(), verb)
    except Exception:                     # noqa: BLE001 - never block on the guard itself
        refused = None
    if refused:
        return CommandResult(False, refused)

    fn = registry.skills[verb]
    try:
        out = fn(args, speaker)
    except Exception as exc:  # noqa: BLE001 - a skill crash is a failed command
        return CommandResult(False, f"{verb} failed: {type(exc).__name__}: {exc}")
    out = str(out).strip()
    return CommandResult(bool(out), out or f"{verb} returned nothing.")
