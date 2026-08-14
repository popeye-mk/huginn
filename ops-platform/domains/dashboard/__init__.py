"""Dashboard domain (G5): assemble the guard's current state, read-only."""

from domains.dashboard.service import (
    DashboardState,
    DeviceRow,
    build_state,
    classify_device,
)

__all__ = ["DashboardState", "DeviceRow", "build_state", "classify_device"]
