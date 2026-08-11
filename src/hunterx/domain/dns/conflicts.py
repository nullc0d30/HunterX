# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS conflict resolution policy.

When several observations of the same name/type disagree, the capability must
pick a canonical value without silently discarding the losers. This module
provides the deterministic resolution policy used by the correlator and the
application layer, plus a helper to annotate records with the conflict they
participated in.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.dns.confidence import DnsConfidenceEngine, DnsConfidencePolicy
from hunterx.domain.dns.correlator import DnsConflict
from hunterx.domain.dns.models import DnsRecord

__all__ = ["DnsConflict", "DnsConflictResolver"]

#: Resolution strategies.
_MOST_CONFIDENT = "most-confident"
_MOST_RECENT = "most-recent"
_ALL_VALUES = "all-values"

_STRATEGIES = (_MOST_CONFIDENT, _MOST_RECENT, _ALL_VALUES)


@dataclass(frozen=True, slots=True)
class DnsConflictResolver:
    """Resolve which value of a conflicting group is canonical.

    Attributes:
        strategy: ``most-confident`` (default), ``most-recent`` or
            ``all-values``.

    """

    strategy: str = _MOST_CONFIDENT

    def __post_init__(self) -> None:
        if self.strategy not in _STRATEGIES:
            raise ValueError(f"unknown conflict strategy '{self.strategy}'")

    def select(self, conflict: DnsConflict, candidates: list[DnsRecord]) -> DnsRecord:
        """Return the canonical record for a conflicting group.

        ``candidates`` are the observations sharing the conflict's name/type.
        The selected record keeps full provenance; losers remain visible through
        the :class:`DnsConflict` returned by the correlator.
        """
        if not candidates:
            raise ValueError("cannot resolve a conflict without candidates")
        if self.strategy == _MOST_RECENT:
            return max(candidates, key=lambda record: record.observed_at)
        if self.strategy == _ALL_VALUES:
            joined = ",".join(sorted({record.value for record in candidates}))
            representative = max(candidates, key=lambda record: record.observed_at)
            return _replace_value(representative, joined, conflict.confidence)
        engine = DnsConfidenceEngine(DnsConfidencePolicy())
        return max(candidates, key=engine.record_confidence)

    def resolve(
        self,
        conflict: DnsConflict,
        candidates: list[DnsRecord],
        confidence: DnsConfidencePolicy | None = None,
    ) -> DnsRecord:
        """Resolve a conflict using the configured strategy.

        The ``confidence`` policy is used for the ``most-confident`` strategy
        when provided.
        """
        if self.strategy != _MOST_CONFIDENT:
            return self.select(conflict, candidates)
        engine = DnsConfidenceEngine(confidence)
        return max(candidates, key=engine.record_confidence)


def _replace_value(record: DnsRecord, value: str, confidence: float) -> DnsRecord:
    """Return a copy of ``record`` with a new value/confidence."""
    return DnsRecord(
        name=record.name,
        record_type=record.record_type,
        value=value,
        raw_value=record.raw_value,
        ttl=record.ttl,
        priority=record.priority,
        source=record.source,
        tool_id=record.tool_id,
        resolver=record.resolver,
        observed_at=record.observed_at,
        execution_id=record.execution_id,
        correlation_id=record.correlation_id,
        target_id=record.target_id,
        validation_status=record.validation_status,
        confidence=confidence,
        record_id=record.record_id,
    )
