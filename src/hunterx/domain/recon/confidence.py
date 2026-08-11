# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance confidence engine.

Assigns a defensible confidence score to every discovery observation and
recomputes it when several tools corroborate the same asset. Confidence is a
pure function of (tool reliability, asset kind, corroboration count) so the
same inputs always yield the same score and scores stay comparable across
runs.

The default policy encodes the observed reliability of the integrated recon
tools for each discovery kind. Subscriber tools (subfinder, amass, bbot) and
active resolvers score higher than opportunistic index-scrapers (assetfinder,
theHarvester).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord

#: Default base reliability per tool (``0.0`` unknown tools score low).
_DEFAULT_BASE: dict[str, float] = {
    "subfinder": 0.90,
    "amass": 0.85,
    "bbot": 0.80,
    "findomain": 0.70,
    "assetfinder": 0.60,
    "theharvester": 0.55,
}

#: Per-kind multiplicative factors; passive-index kinds are discounted.
_KIND_FACTORS: dict[DiscoveryKind, float] = {
    DiscoveryKind.DOMAIN: 1.0,
    DiscoveryKind.SUBDOMAIN: 1.0,
    DiscoveryKind.HOSTNAME: 0.95,
    DiscoveryKind.IP_ADDRESS: 0.9,
    DiscoveryKind.CIDR: 0.85,
    DiscoveryKind.ASN: 0.8,
    DiscoveryKind.DNS_RECORD: 0.9,
    DiscoveryKind.CERTIFICATE: 0.9,
    DiscoveryKind.WHOIS: 0.8,
    DiscoveryKind.ORGANIZATION: 0.7,
    DiscoveryKind.CLOUD_PROVIDER: 0.7,
    DiscoveryKind.EXPOSED_ASSET: 0.6,
}


@dataclass(frozen=True, slots=True)
class ConfidencePolicy:
    """Configuration governing confidence scoring.

    Attributes:
        base: map of ``tool_id`` to base reliability in ``[0, 1]``.
        kind_factors: map of :class:`DiscoveryKind` to a multiplicative factor.
        corroboration_boost: confidence added per corroborating tool beyond
            the strongest one.
        max_confidence: ceiling applied to every computed score.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    kind_factors: Mapping[DiscoveryKind, float] = field(default_factory=lambda: dict(_KIND_FACTORS))
    corroboration_boost: float = 0.1
    max_confidence: float = 1.0

    def factor_for(self, kind: DiscoveryKind) -> float:
        """Return the kind factor, defaulting to ``1.0`` when unset."""
        return self.kind_factors.get(kind, 1.0)

    def base_for(self, tool_id: str) -> float:
        """Return the base reliability for ``tool_id`` (``0.2`` when unknown)."""
        return self.base.get(tool_id, 0.2)


class ConfidenceEngine:
    """Compute and merge confidence scores for discovery records.

    Usage::

        engine = ConfidenceEngine()
        score = engine.source_confidence("subfinder", DiscoveryKind.SUBDOMAIN)
        merged = engine.merged_confidence(records)
    """

    def __init__(self, policy: ConfidencePolicy | None = None) -> None:
        self._policy = policy or ConfidencePolicy()

    @property
    def policy(self) -> ConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def source_confidence(self, tool_id: str, kind: DiscoveryKind) -> float:
        """Return the base confidence for a tool observing ``kind``."""
        return _clamp(self._policy.base_for(tool_id) * self._policy.factor_for(kind), self._policy)

    def record_confidence(self, record: DiscoveryRecord) -> float:
        """Return the confidence of a single record.

        The record's observed confidence (from the parser) is weighted by the
        tool's reliability so a low-trust tool cannot inflate a score.
        """
        weight = self._policy.base_for(record.tool_id)
        return _clamp(record.confidence * weight, self._policy)

    def merged_confidence(self, records: Sequence[DiscoveryRecord]) -> float:
        """Compute the confidence of a corroborated asset group.

        Uses the strongest individual score and adds a boost for every
        distinct corroborating tool beyond the first.
        """
        if not records:
            return 0.0
        strongest = max(self.record_confidence(record) for record in records)
        distinct_tools = {record.tool_id for record in records if record.tool_id}
        boost = self._policy.corroboration_boost * max(0, len(distinct_tools) - 1)
        return _clamp(strongest + boost, self._policy)

    def promote(self, record: DiscoveryRecord, merged: float) -> DiscoveryRecord:
        """Return ``record`` with ``confidence`` replaced by ``merged``."""
        if abs(record.confidence - merged) < 1e-9:
            return record
        return DiscoveryRecord(
            kind=record.kind,
            name=record.name,
            tool_id=record.tool_id,
            source=record.source,
            confidence=merged,
            target_id=record.target_id,
            details=record.details,
            observed_at=record.observed_at,
            record_id=record.record_id,
        )


def _clamp(value: float, policy: ConfidencePolicy) -> float:
    """Clamp ``value`` into ``[0, max_confidence]``."""
    return max(0.0, min(policy.max_confidence, value))
