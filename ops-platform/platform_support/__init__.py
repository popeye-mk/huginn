"""OS abstraction. The only layer permitted to branch on platform."""

from .detect import (
    LINUX,
    MACOS,
    WINDOWS,
    binary_name,
    current_os,
    hostname,
    is_linux,
    is_windows,
    os_label,
    python_executable,
    resolve_binary,
)
from .commands import (
    connection_command,
    connection_output_is_json,
    firewall_command,
    ipv6_ra_command,
    listening_ports_command,
    llmnr_setting_command,
)
from .sandbox_kind import (
    HYPERV,
    KVM,
    SANDBOX_KINDS,
    sandbox_kind,
    sandbox_unsupported_reason,
)

__all__ = [
    "current_os", "is_windows", "is_linux", "hostname",
    "binary_name", "resolve_binary", "python_executable", "os_label",
    "WINDOWS", "LINUX", "MACOS",
    "sandbox_kind", "sandbox_unsupported_reason",
    "SANDBOX_KINDS", "KVM", "HYPERV",
    "connection_command", "connection_output_is_json",
    "listening_ports_command", "llmnr_setting_command",
    "ipv6_ra_command", "firewall_command",
]
