# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology confidence engine.

Merges per-source confidence into a single edge confidence and models
temporal decay for staleness analysis. All rules are deterministic so repeated
runs over the same evidence produce identical numbers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

#: Reliability weight per provenance source family; unknown sources default to 1.0.
_SOURCE_RELIABILITY: dict[str, float] = {
    "tidb": 1.0,
    "tidb:domain": 1.0,
    "tidb:hostname": 1.0,
    "tidb:ip": 1.0,
    "tidb:certificate": 1.0,
    "tidb:dns_record": 1.0,
    "nmap": 0.95,
    "naabu": 0.9,
    "masscan": 0.85,
    "traceroute": 0.8,
    "subfinder": 0.8,
    "amass": 0.85,
    "assetfinder": 0.75,
    "findomain": 0.8,
    "bbot": 0.85,
    "theharvester": 0.7,
    "analysis": 0.9,
    "derived": 0.9,
}


class TopologyConfidenceEngine:
    """Compute merged confidence and temporal decay."""

    def __init__(self, reliability: Mapping[str, float] | None = None) -> None:
        self._reliability = dict(reliability) if reliability else dict(_SOURCE_RELIABILITY)

    def source_weight(self, source_name: str) -> float:
        """Return the reliability weight for a provenance source."""
        return self._reliability.get(source_name, self._reliability.get(source_name.split(":")[0], 1.0))

    def combine(self, confidences: Sequence[float], *, source_names: Sequence[str] | None = None) -> float:
        """Merge observation confidences into a single value.

        Uses the probabilistic sum ``1 - prod(1 - c_i)`` scaled by source
        reliability, capped at 0.99 to avoid over-confidence.
        """
        values = list(confidences)
        if not values:
            return 0.0
        if source_names:
            values = [
                min(1.0, c * self.source_weight(name)) for c, name in zip(values, source_names, strict=False)
            ]
        product = 1.0
        for value in values:
            product *= max(0.0, 1.0 - value)
        return round(min(0.99, 1.0 - product), 4)

    def decay(self, confidence: float, *, age_days: float, half_life_days: float = 90.0) -> float:
        """Decay a confidence by elapsed time (halving every ``half_life_days``)."""
        if half_life_days <= 0:
            return confidence
        return round(max(0.0, confidence * (0.5 ** (max(0.0, age_days) / half_life_days))), 4)

    def is_stale(self, *, last_seen: str, now: str, max_age_days: float = 90.0) -> bool:
        """Return ``True`` when an observation is older than ``max_age_days``."""
        from hunterx.shared.time import to_utc_datetime

        try:
            seen = to_utc_datetime(last_seen)
            current = to_utc_datetime(now)
            age = (current - seen).total_seconds() / 86400.0
        except ValueError:
            return False
        return age > max_age_days

    def attribute(self, observations: Sequence[Any]) -> float:
        """Return the merged confidence of a list of observations."""
        return self.combine(
            [float(o.confidence) for o in observations],
            source_names=[str(o.source_name) for o in observations],
        )


def entity_confidence(meta: Mapping[str, Any], default: float = 1.0) -> float:
    """Read a confidence value from an entity ``meta`` map when present."""
    value = meta.get("confidence")
    if isinstance(value, (int, float)):
        return float(value)
    return default
