"""Backup domain — restore verification and sandbox lifecycle.

Owns one question: *if this machine died tonight, would the backup bring
it back?* Everything here exists to answer that with evidence rather
than with the backup software's own opinion of itself.
"""

from .disk_image import DiskImageSearch, find_disk_image
from .repository import VerificationRepository
from .service import BackupService

__all__ = [
    "BackupService", "VerificationRepository",
    "find_disk_image", "DiskImageSearch",
]
