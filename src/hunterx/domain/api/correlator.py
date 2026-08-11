# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API observation correlation.

Correlates raw API intelligence observations into a canonical inventory: API
hosts are keyed by origin, endpoint operations by (method, normalized path),
spec documents by source URL and auth observations by scheme. Duplicate
records from different sources are merged; corroborated records boost
confidence; conflicts are delegated to the conflict resolver.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from hunterx.domain.api.confidence import ApiConfidenceEngine
from hunterx.domain.api.conflicts import ApiConflictResolver
from hunterx.domain.api.models import (
    ApiAuthObservation,
    ApiConflict,
    ApiFilterObservation,
    APIHostObservation,
    ApiOperationObservation,
    ApiPaginationObservation,
    ApiRateLimitObservation,
    APISpecObservation,
)


@dataclass(slots=True)
class CorrelationResult:
    """The correlation outcome for one run.

    Attributes:
        hosts: correlated API hosts.
        specs: correlated spec documents.
        operations: correlated endpoint operations.
        auth: correlated auth observations.
        rate_limits / paginations / filters: derived indicator records.
        conflicts: conflicts the resolver preserved.
        raw_count: number of raw observations consumed.

    """

    hosts: list[APIHostObservation] = field(default_factory=list)
    specs: list[APISpecObservation] = field(default_factory=list)
    operations: list[ApiOperationObservation] = field(default_factory=list)
    auth: list[ApiAuthObservation] = field(default_factory=list)
    rate_limits: list[ApiRateLimitObservation] = field(default_factory=list)
    paginations: list[ApiPaginationObservation] = field(default_factory=list)
    filters: list[ApiFilterObservation] = field(default_factory=list)
    conflicts: list[ApiConflict] = field(default_factory=list)
    raw_count: int = 0

    def __len__(self) -> int:
        """Return the number of correlated records."""
        return (
            len(self.hosts)
            + len(self.specs)
            + len(self.operations)
            + len(self.auth)
            + len(self.rate_limits)
            + len(self.paginations)
            + len(self.filters)
        )


class ApiCorrelator:
    """Correlate raw observations into canonical records.

    Usage::

        correlator = ApiCorrelator(confidence=ApiConfidenceEngine(), conflicts=ApiConflictResolver())
        result = correlator.correlate(raw_observations)
    """

    def __init__(
        self,
        *,
        confidence: ApiConfidenceEngine | None = None,
        conflicts: ApiConflictResolver | None = None,
    ) -> None:
        self._confidence = confidence or ApiConfidenceEngine()
        self._conflicts = conflicts or ApiConflictResolver()

    def correlate(self, raw: Iterable[Any]) -> CorrelationResult:
        """Collapse raw observations into a canonical inventory."""
        raw_items = list(raw)
        hosts: dict[str, APIHostObservation] = {}
        specs: dict[str, APISpecObservation] = {}
        operations: dict[str, dict[str, ApiOperationObservation]] = {}
        auth: dict[str, ApiAuthObservation] = {}
        rate_limits: dict[str, ApiRateLimitObservation] = {}
        paginations: dict[str, ApiPaginationObservation] = {}
        filters: dict[str, ApiFilterObservation] = {}
        conflicts: list[ApiConflict] = []

        for item in raw_items:
            if isinstance(item, APIHostObservation):
                key = item.key()
                existing = hosts.get(key)
                if existing is None or _replacement_priority(item) > _replacement_priority(existing):
                    hosts[key] = item
            elif isinstance(item, APISpecObservation):
                key = item.key()
                existing = specs.get(key)
                if existing is None or _replacement_priority(item) > _replacement_priority(existing):
                    specs[key] = item
            elif isinstance(item, ApiOperationObservation):
                key = item.key()
                bucket = operations.setdefault(key, {})
                bucket[item.source or item.tool_id] = item
            elif isinstance(item, ApiAuthObservation):
                key = item.key()
                existing = auth.get(key)
                if existing is None or _replacement_priority(item) > _replacement_priority(existing):
                    auth[key] = item
            elif isinstance(item, ApiRateLimitObservation):
                key = item.key()
                existing = rate_limits.get(key)
                if existing is None or item.confidence > existing.confidence:
                    rate_limits[key] = item
            elif isinstance(item, ApiPaginationObservation):
                key = item.key()
                existing = paginations.get(key)
                if existing is None or item.confidence > existing.confidence:
                    paginations[key] = item
            elif isinstance(item, ApiFilterObservation):
                key = item.key()
                existing = filters.get(key)
                if existing is None or item.confidence > existing.confidence:
                    filters[key] = item

        # Resolve per-operation duplicates and conflicts.
        correlated_operations: list[ApiOperationObservation] = []
        for key, bucket in operations.items():
            resolved, conflict = self._resolve_operation(key, list(bucket.values()))
            if conflict is not None:
                conflicts.append(conflict)
            if resolved is not None:
                correlated_operations.append(resolved)

        return CorrelationResult(
            hosts=list(hosts.values()),
            specs=list(specs.values()),
            operations=correlated_operations,
            auth=list(auth.values()),
            rate_limits=list(rate_limits.values()),
            paginations=list(paginations.values()),
            filters=list(filters.values()),
            conflicts=conflicts,
            raw_count=len(raw_items),
        )

    def _resolve_operation(
        self,
        key: str,
        candidates: Sequence[ApiOperationObservation],
    ) -> tuple[ApiOperationObservation | None, ApiConflict | None]:
        """Merge duplicate operation candidates and detect disagreements."""
        if not candidates:
            return None, None
        if len(candidates) == 1:
            return candidates[0], None

        truth = max(candidates, key=_operation_truth_rank)
        conflict = self._conflicts.detect_operation_conflict(truth, candidates)
        if conflict is not None:
            resolved = self._conflicts.resolve_operation(truth, candidates)
            return resolved, conflict

        # Corroboration: merge sources and evidence; recompute confidence.
        sources: list[str] = []
        evidence: list[object] = []
        documented = any(item.documented for item in candidates)
        for item in candidates:
            sources.extend(item.sources or (item.tool_id,))
            evidence.extend(item.evidence)

        merged = replace(
            truth,
            documented=documented,
            confidence=self._confidence.score_operation(
                truth,
                corroborated_by=len(candidates),
            ),
            sources=tuple(dict.fromkeys(sources)),
            evidence=tuple(dict.fromkeys(evidence)),
        )
        return merged, None


def _replacement_priority(item: Any) -> int:
    """Return a deterministic priority for duplicate replacement."""
    documented = bool(getattr(item, "documented", False))
    source = str(getattr(item, "source", "") or "")
    priority = 0
    if documented:
        priority += 10
    if source in ("api-openapi", "api-swagger", "api-soap"):
        priority += 5
    elif source in ("web.crawl", "web", "crawler"):
        priority += 2
    return priority


def _operation_truth_rank(item: ApiOperationObservation) -> int:
    """Rank an operation candidate as the truth source (documented specs win)."""
    documented = 1 if item.documented else 0
    priority = _replacement_priority(item)
    return documented * 100 + priority
