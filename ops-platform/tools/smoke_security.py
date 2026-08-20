"""R8 smoke checks: connections and threat feeds.

Split from `smoke_test.py` when it crossed the 400-line limit. The seam
is by subject, not by size: these arrived with R8 and will keep growing
as feeds and observation do, while the engine and contract checks have
been stable since R0.

Registered by calling `register(check, SkipCheck)` — the decorator and
the skip exception are passed in rather than imported, because importing
them would run `smoke_test` a second time and every check with it.
"""


def register(check, SkipCheck):
    """Attach these checks to the smoke test's registry.

    Delegates rather than holding every check itself: four nested
    functions in one `register` is a 100-line function wearing a
    decorator as a disguise, and the size rule was right to say so.
    """
    _register_connections(check, SkipCheck)
    _register_backup(check, SkipCheck)


def _observe_connections() -> str:
    """The R8 input, on whichever OS this is.

    Reports raw payload size **and** parsed count, because a parse that
    silently returns zero rows would look identical to a quiet machine.
    That distinction earned its keep immediately: it caught a Linux bug
    where `ss` returned TIME-WAIT rows the parser was discarding, before
    the Windows disc was even built.
    """
    from domains.network.connections import (
        parse_linux, parse_macos, parse_windows,
    )
    from engines.connections import ConnectionsEngine
    from platform_support import connection_format

    engine = ConnectionsEngine()
    if not engine.is_available():
        raise RuntimeError("the connection listing tool did not run")

    output = engine.run()
    # The parser choice MUST come from the same source the product uses
    # (`connection_format`), or this check drifts from reality. It did: this
    # branch used to be "not JSON, so Linux", which mis-parsed every macOS
    # row while the product's own path had already been taught the BSD form.
    fmt = connection_format()
    if fmt == "json":
        payload = output.payload
        rows = len(payload) if isinstance(payload, list) else (1 if payload else 0)
        parsed = parse_windows(payload)
    else:
        rows = len([ln for ln in (output.payload or "").splitlines() if ln.strip()])
        parsed = parse_macos(output.payload) if fmt == "bsd" else parse_linux(output.payload)

    if rows and not parsed:
        raise RuntimeError(
            f"{rows} row(s) returned but none parsed — parser does not "
            f"match this OS's output format"
        )
    external = sum(1 for c in parsed if c.is_external)
    return f"{rows} row(s) -> {len(parsed)} parsed, {external} external"


def _feed_state(SkipCheck) -> str:
    """Feeds are optional; lying about them is not.

    Absent feeds SKIP, because nobody has downloaded them yet on a fresh
    machine. A feed that loaded but cannot be parsed FAILS, because that
    is a bug rather than a configuration state — precisely what happened
    on the first live run, when a ThreatFox-only parser read Feodo
    Tracker and reported "empty".
    """
    from storage.threat_feed import load_feeds

    feeds = load_feeds()
    if not feeds:
        raise SkipCheck("no feeds downloaded (tools/update_feeds.py)")

    broken = [f.status.summary for f in feeds if f.status.unparseable_rows]
    if broken:
        raise RuntimeError("; ".join(broken))

    usable = [f for f in feeds if f.status.is_usable]
    indicators = sum(f.status.entry_count for f in usable)
    return f"{len(usable)}/{len(feeds)} usable, {indicators:,} indicators"


def _register_connections(check, SkipCheck):
    """Checks for what this machine is talking to, and what we know."""

    @check("connections: engine lists this machine's connections")
    def _connections_engine():
        return _observe_connections()

    @check("threat: feeds report their own state honestly")
    def _threat_feeds():
        return _feed_state(SkipCheck)


def _register_backup(check, SkipCheck):
    """Checks for restore verification and its sandbox."""

    @check("backup: sandbox kind resolves for this OS")
    def _sandbox_kind():
        """Which hypervisor this OS would use — KVM on Linux, Hyper-V on
        Windows. Checked on both because it is the one piece of R7
        guaranteed to differ, and a wrong answer means boot verification
        silently never runs."""
        from platform_support import sandbox_kind, sandbox_unsupported_reason

        kind = sandbox_kind()
        if not kind:
            raise SkipCheck(sandbox_unsupported_reason())
        return f"resolved {kind}"

    @check("backup: verification refuses to claim without evidence")
    def _backup_honesty():
        """An unverifiable backup must report NOT_ATTEMPTED, never a pass.

        The check most likely to catch a regression that matters: a
        future change making a missing restic look like a clean result
        would pass every other test in the suite.
        """
        from contracts import VerificationStatus
        from domains.backup import BackupService

        service = BackupService()
        verification = service.verify("smoke-test")
        if verification.is_proof_of_recovery:
            raise RuntimeError(
                "claimed proof of recovery without restoring anything"
            )
        if not service.is_available():
            if verification.status is not VerificationStatus.NOT_ATTEMPTED:
                raise RuntimeError(
                    f"restic absent but status was {verification.status.value}"
                )
            return "restic absent — reported as not verified, correctly"
        return (
            f"restic present — {verification.status.value} "
            f"at {verification.depth.value}"
        )
