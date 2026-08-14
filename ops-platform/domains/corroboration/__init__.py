"""Corroboration domain: what two or more hosts saw, compared."""

from domains.corroboration.service import (
    DEFAULT_MAX_AGE_MINUTES,
    age_minutes,
    assess,
    distinct_hosts,
    fresh,
    gateway_disagreement,
    only_one_host_sees,
    saw_nothing,
    segments,
    verdict,
)

__all__ = ["DEFAULT_MAX_AGE_MINUTES", "age_minutes", "assess", "distinct_hosts",
           "fresh", "gateway_disagreement", "only_one_host_sees", "saw_nothing",
           "segments", "verdict"]
