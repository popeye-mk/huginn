"""Typed errors shared across layers.

One hierarchy so callers can catch by category rather than by string
matching on messages. Every error carries enough context to be shown to
an operator without consulting a log file — this platform's users are
one person with no time, not an SRE team with dashboards.
"""


class OpsPlatformError(Exception):
    """Base for every error this platform raises deliberately."""


class EngineError(OpsPlatformError):
    """An external tool could not be run, or its output made no sense."""

    def __init__(self, engine: str, message: str, detail: str = ""):
        self.engine = engine
        self.detail = detail
        super().__init__(f"[{engine}] {message}")


class EngineNotFoundError(EngineError):
    """The tool is not installed or not where we expected it."""


class EngineTimeoutError(EngineError):
    """The tool ran too long and was stopped."""


class EngineOutputError(EngineError):
    """The tool ran but produced output we could not parse."""


class ContractViolation(OpsPlatformError):
    """Data did not match its contract.

    Distinct from a plain ValueError so mapping bugs are separable from
    ordinary bad input.
    """


class UnsupportedPlatformError(OpsPlatformError):
    """This operation has no implementation for the current OS.

    Raised loudly rather than silently skipping, because a backup
    verification that quietly does nothing on Windows is worse than one
    that refuses to run.
    """

    def __init__(self, operation: str, current_os: str, supported: tuple = ()):
        self.operation = operation
        self.current_os = current_os
        self.supported = supported
        supported_text = ", ".join(supported) if supported else "none yet"
        super().__init__(
            f"{operation} is not implemented on {current_os} "
            f"(supported: {supported_text})"
        )


class RepositoryError(OpsPlatformError):
    """Persistence failed."""
