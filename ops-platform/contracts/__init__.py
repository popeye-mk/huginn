"""Shared data contracts. Pure types — no logic, no I/O.

Everything above this layer speaks these types. Engines map their native
output into them; they never leak tool-specific shapes upward.
"""

from .indicator import IOC_TYPES, MATCHABLE_TYPES, Indicator
from .connection import PROTOCOLS, TRACKED_STATES, Connection
from .citation import GROUNDED, NO_KB, NO_MATCH, NOT_REQUESTED, Citation
from .command_result import CommandResult
from .correlation import Correlation
from .device import Device, DeviceHealth, DISCOVERY_SOURCES
from .errors import (
    ContractViolation,
    EngineError,
    EngineNotFoundError,
    EngineOutputError,
    EngineTimeoutError,
    OpsPlatformError,
    RepositoryError,
    UnsupportedPlatformError,
)
from .finding import (
    CONFIDENCES,
    SEVERITIES,
    SOURCE_MODULES,
    Coverage,
    Finding,
    sort_findings,
)
from .verification import (
    RestoreVerification,
    VerificationCheck,
    VerificationDepth,
    VerificationStatus,
)

__all__ = [
    # finding
    "Finding", "Coverage", "sort_findings",
    "SEVERITIES", "CONFIDENCES", "SOURCE_MODULES",
    # correlation
    "Correlation",
    # citation
    "Citation", "GROUNDED", "NO_KB", "NO_MATCH", "NOT_REQUESTED",
    # command result (assistant-shell envelope)
    "CommandResult",
    # connection
    "Connection", "PROTOCOLS", "TRACKED_STATES",
    # indicator
    "Indicator", "IOC_TYPES", "MATCHABLE_TYPES",
    # device
    "Device", "DeviceHealth", "DISCOVERY_SOURCES",
    # verification
    "RestoreVerification", "VerificationCheck", "VerificationStatus",
    "VerificationDepth",
    # errors
    "OpsPlatformError", "EngineError", "EngineNotFoundError",
    "EngineTimeoutError", "EngineOutputError", "ContractViolation",
    "UnsupportedPlatformError", "RepositoryError",
]
