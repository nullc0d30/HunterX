# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS confidence engine.

Assigns a defensible, deterministic confidence score to every DNS observation
and recomputes it when several tools or resolvers corroborate the same record.
Confidence is a pure function of (source reliability, validation status,
corroboration count, freshness, resolver agreement and historical stability) —
the same inputs always yield the same score and the score is explainable
through the factors that contributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hunterx.domain.dns.models import DnsRecord

#: Default base reliability per tool (``0.2`` unknown tools score low).
_DEFAULT_BASE: dict[str, float] = {
    "dnsx": 0.92,
    "dnspython": 0.85,
}

#: Multiplicative factor per validation status.
_VALIDATION_FACTORS: Mapping[str, float] = {
    "valid": 1.0,
    "unknown": 0.75,
    "invalid": 0.3,
}

#: Per-distinct-resolver agreement boost applied beyond the first resolver.
_RESOLVER_BOOST = 0.05

#: Per-tool corroboration boost applied beyond the strongest tool.
_CORROBORATION_BOOST = 0.08


@dataclass(frozen=True, slots=True)
class DnsConfidencePolicy:
    """Configuration governing DNS confidence scoring.

    Attributes:
        base: map of ``tool_id`` to base reliability in ``[0, 1]``.
        validation_factors: map of validation status to a multiplicative factor.
        resolver_boost: confidence added per agreeing resolver beyond the first.
        corroboration_boost: confidence added per corroborating tool beyond
            the strongest one.
        max_confidence: ceiling applied to every computed score.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    validation_factors: Mapping[str, float] = field(default_factory=lambda: dict(_VALIDATION_FACTORS))
    resolver_boost: float = _RESOLVER_BOOST
    corroboration_boost: float = _CORROBORATION_BOOST
    max_confidence: float = 1.0

    def base_for(self, tool_id: str) -> float:
        """Return the base reliability for ``tool_id`` (``0.2`` when unknown)."""
        return self.base.get(tool_id, 0.2)

    def validation_factor(self, status: str) -> float:
        """Return the factor for a validation status (``0.5`` when unset)."""
        return self.validation_factors.get(status, 0.5)


class DnsConfidenceEngine:
    """Compute and merge confidence scores for DNS records.

    Usage::

        engine = DnsConfidenceEngine()
        score = engine.record_confidence(record)
        merged = engine.merged_confidence(records)
    """

    def __init__(self, policy: DnsConfidencePolicy | None = None) -> None:
        self._policy = policy or DnsConfidencePolicy()

    @property
    def policy(self) -> DnsConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def record_confidence(self, record: DnsRecord) -> float:
        """Return the confidence of a single record.

        Combines the tool's reliability, the validation status, and the number
        of distinct resolvers that corroborated the observation.
        """
        base = self._policy.base_for(record.tool_id)
        validation = self._policy.validation_factor(record.validation_status)
        resolvers = _resolver_count(record)
        resolver_boost = self._policy.resolver_boost * max(0, resolvers - 1)
        return _clamp(base * validation + resolver_boost, self._policy)

    def merged_confidence(self, records: Sequence[DnsRecord]) -> float:
        """Compute the confidence of a corroborated record group.

        Uses the strongest individual score and adds a boost for every distinct
        corroborating tool beyond the first.
        """
        if not records:
            return 0.0
        strongest = max(self.record_confidence(record) for record in records)
        distinct_tools = {record.tool_id for record in records if record.tool_id}
        boost = self._policy.corroboration_boost * max(0, len(distinct_tools) - 1)
        return _clamp(strongest + boost, self._policy)

    def historical_confidence(self, base: float, *, observations: int, stable: bool) -> float:
        """Adjust a confidence for historical stability.

        Records that have been observed many times or that have remained stable
        across observations are more trustworthy.
        """
        stability = 1.0 if stable else 0.9
        history = min(1.0, 0.8 + 0.05 * max(0, observations - 1))
        return _clamp(base * stability * history, self._policy)

    def freshness_confidence(self, base: float, *, age_hours: float) -> float:
        """Decay a confidence score as an observation ages.

        ``age_hours <= 0`` yields no decay; older observations fade toward a
        floor of ``0.5 * base``.
        """
        if age_hours <= 0:
            return _clamp(base, self._policy)
        factor = max(0.5, 1.0 - age_hours / 24.0)
        return _clamp(base * factor, self._policy)


def _resolver_count(record: DnsRecord) -> int:
    """Return the number of resolvers encoded in the record's provenance.

    The resolver field can hold a comma-separated list when an adapter merges
    answers from several resolvers for one record.
    """
    if not record.resolver:
        return 1
    return max(1, len([part for part in record.resolver.split(",") if part.strip()]))


def _clamp(value: float, policy: DnsConfidencePolicy) -> float:
    """Clamp ``value`` into ``[0, max_confidence]``."""
    return max(0.0, min(policy.max_confidence, value))
