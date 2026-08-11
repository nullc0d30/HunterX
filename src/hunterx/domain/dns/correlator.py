# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""DNS correlation and conflict detection.

Correlates DNS observations from multiple tools/resolvers/executions into a
single canonical record set, merging corroborating answers and surfacing
conflicts. The correlator never silently discards an observation: values that
disagree across sources are reported as conflicts with full provenance.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from hunterx.domain.dns.confidence import DnsConfidenceEngine, DnsConfidencePolicy
from hunterx.domain.dns.models import DnsRecord, DnsRecordType
from hunterx.domain.dns.scope import ScopeEnforcer, ScopePolicy


@dataclass(frozen=True, slots=True)
class DnsCorrelationResult:
    """The outcome of correlating a set of DNS observations.

    Attributes:
        records: the canonical, merged records (one per name/type/value).
        conflicts: observations that disagreed with the merged value.
        scoped_out: observations removed by scope enforcement.
        merged: number of observations merged into canonical records.

    """

    records: tuple[DnsRecord, ...]
    conflicts: tuple[DnsConflict, ...] = ()
    scoped_out: int = 0
    merged: int = 0


def correlate_records(
    records: Iterable[DnsRecord],
    *,
    scope: ScopePolicy | None = None,
    confidence: DnsConfidencePolicy | None = None,
) -> DnsCorrelationResult:
    """Correlate ``records`` into a canonical set.

    Records are keyed by ``(name, record_type, value)``. Observations sharing a
    key are merged (source and resolver provenance accumulated, confidence
    raised by corroboration). Distinct values for the same name/type produce a
    :class:`DnsConflict`. Scope enforcement drops out-of-scope records.
    """
    engine = DnsConfidenceEngine(confidence)
    scope_enforcer = ScopeEnforcer(scope)
    grouped: dict[str, list[DnsRecord]] = {}
    conflicts: list[DnsConflict] = []
    scoped_out = 0
    for record in records:
        if not scope_enforcer.allows_record(record):
            scoped_out += 1
            continue
        key = _record_key(record)
        grouped.setdefault(key, []).append(record)

    canonical: list[DnsRecord] = []
    seen_values: dict[str, dict[str, DnsRecord]] = {}
    for _key, observations in grouped.items():
        canonical_record = _merge_observations(observations, engine)
        canonical.append(canonical_record)
        group_key = _group_key(observations[0])
        seen_values.setdefault(group_key, {})[canonical_record.value] = canonical_record

    for _key, observations in grouped.items():
        first = observations[0]
        group_key = _group_key(first)
        group_records = seen_values[group_key]
        if len(group_records) > 1:
            conflicts.append(
                DnsConflict(
                    name=first.name,
                    record_type=first.record_type,
                    values=tuple(sorted(group_records.keys())),
                    sources=tuple(sorted({source for rec in observations for source in (rec.source,) if source})),
                    resolvers=tuple(sorted({res for rec in observations for res in _split_resolvers(rec)})),
                    selected=canonical_record.value,
                    confidence=canonical_record.confidence,
                    reason="conflicting answers observed across sources",
                )
            )

    merged = sum(1 for _records in grouped.values() if len(_records) > 1)
    return DnsCorrelationResult(
        records=tuple(canonical),
        conflicts=tuple(_dedupe_conflicts(conflicts)),
        scoped_out=scoped_out,
        merged=merged,
    )


class DnsCorrelator:
    """Object-style correlator wrapping :func:`correlate_records`."""

    def __init__(self, scope: ScopePolicy | None = None, confidence: DnsConfidencePolicy | None = None) -> None:
        self._scope = scope
        self._confidence = confidence

    def correlate(self, records: Iterable[DnsRecord]) -> DnsCorrelationResult:
        """Correlate ``records`` and return the result."""
        return correlate_records(records, scope=self._scope, confidence=self._confidence)


@dataclass(frozen=True, slots=True)
class DnsConflict:
    """A disagreement between observations of the same DNS name/type.

    Attributes:
        name: the owner name.
        record_type: the record type.
        values: the distinct values observed.
        sources: the distinct sources (tools) that produced the values.
        resolvers: the distinct resolvers involved.
        selected: the value selected as canonical (highest-confidence).
        confidence: confidence of the selected value.
        reason: human-readable explanation.

    """

    name: str
    record_type: DnsRecordType
    values: tuple[str, ...]
    sources: tuple[str, ...]
    resolvers: tuple[str, ...]
    selected: str
    confidence: float
    reason: str = "conflicting answers observed"


def _record_key(record: DnsRecord) -> str:
    """Return the merge key for a record (name/type/value)."""
    return f"{record.name.lower()}|{record.record_type.value}|{record.value.strip().lower()}"


def _group_key(record: DnsRecord) -> str:
    """Return the conflict-group key (name/type)."""
    return f"{record.name.lower()}|{record.record_type.value}"


def _merge_observations(observations: list[DnsRecord], engine: DnsConfidenceEngine) -> DnsRecord:
    """Merge observations sharing a key into one canonical record."""
    first = observations[0]
    sources = sorted({record.source for record in observations if record.source})
    resolvers = sorted({res for record in observations for res in _split_resolvers(record)})
    merged_resolver = ",".join(resolvers) if resolvers else first.resolver
    merged_source = ",".join(sources) if sources else first.source
    observed_at = min(record.observed_at for record in observations)
    confidence = engine.merged_confidence(observations)
    return DnsRecord(
        name=first.name,
        record_type=first.record_type,
        value=first.value,
        raw_value=first.raw_value,
        ttl=max((record.ttl for record in observations if record.ttl is not None), default=None),
        priority=first.priority,
        source=merged_source,
        tool_id=first.tool_id,
        resolver=merged_resolver,
        observed_at=observed_at,
        execution_id=first.execution_id,
        correlation_id=first.correlation_id,
        target_id=first.target_id,
        validation_status=first.validation_status,
        confidence=confidence,
        record_id=first.record_id,
    )


def _split_resolvers(record: DnsRecord) -> list[str]:
    """Split a record's comma-joined resolver list."""
    if not record.resolver:
        return []
    return [part for part in record.resolver.split(",") if part.strip()]


def _dedupe_conflicts(conflicts: Iterable[DnsConflict]) -> list[DnsConflict]:
    """Dedupe conflicts that repeat the same name/type/selected tuple."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[DnsConflict] = []
    for conflict in conflicts:
        key = (conflict.name.lower(), conflict.record_type.value, conflict.selected)
        if key in seen:
            continue
        seen.add(key)
        unique.append(conflict)
    return unique
