"""LAN exposure domain (G2): turn open ports into severity-ranked findings."""

from domains.exposure.service import (
    ExposureResult,
    ack_id,
    add_ack,
    assess,
    load_acks,
    load_exposure_baseline,
    save_acks,
    save_exposure_baseline,
)

__all__ = [
    "ExposureResult",
    "ack_id",
    "add_ack",
    "assess",
    "load_acks",
    "load_exposure_baseline",
    "save_acks",
    "save_exposure_baseline",
]
