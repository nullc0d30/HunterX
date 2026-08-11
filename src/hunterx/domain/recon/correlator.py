# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Reconnaissance correlator.

Merges raw discovery records produced by several tools into one deduplicated,
confidence-weighted set. Two records describe the same asset when they share a
canonical :meth:`DiscoveryRecord.key`; the correlator keeps the strongest
observation, folds corroborating evidence into its ``details`` and recomputes
the confidence from the corroboration count.

An optional scope filter drops out-of-scope hostname-like records (records for
a different domain) while always retaining address-space and metadata records
(IPs, CIDRs, ASNs, DNS, certificates, WHOIS) that descend from in-scope hosts.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

from hunterx.domain.recon.confidence import ConfidenceEngine
from hunterx.domain.recon.models import DiscoveryKind, DiscoveryRecord

_SCOPE_KINDS = frozenset(
    {
        DiscoveryKind.DOMAIN,
        DiscoveryKind.SUBDOMAIN,
        DiscoveryKind.HOSTNAME,
        DiscoveryKind.EXPOSED_ASSET,
    }
)


class ReconCorrelator:
    """Deduplicate and merge discovery records across tools.

    Usage::

        correlator = ReconCorrelator()
        merged = correlator.correlate(records, scope="example.com")
    """

    def __init__(self, confidence: ConfidenceEngine | None = None) -> None:
        self._confidence = confidence or ConfidenceEngine()

    @property
    def confidence(self) -> ConfidenceEngine:
        """Return the confidence engine used for scoring."""
        return self._confidence

    def correlate(
        self,
        records: Sequence[DiscoveryRecord],
        *,
        scope: str = "",
    ) -> list[DiscoveryRecord]:
        """Merge ``records`` into a deduplicated, confidence-weighted list.

        Args:
            records: raw records collected from one or more tools.
            scope: optional in-scope domain. When provided, hostname-like
                records outside it are dropped.

        Returns:
            The merged records, ordered by kind then name.

        """
        groups: dict[tuple[DiscoveryKind, str], list[DiscoveryRecord]] = defaultdict(list)
        for record in records:
            if not self._in_scope(record, scope):
                continue
            groups[(record.kind, record.key())].append(record)

        merged = [self._merge(group) for group in groups.values()]
        merged.sort(key=lambda record: (record.kind.value, record.name))
        return merged

    def _in_scope(self, record: DiscoveryRecord, scope: str) -> bool:
        """Return ``True`` when ``record`` belongs to the scope domain."""
        if not scope:
            return True
        if record.kind not in _SCOPE_KINDS:
            return True
        scope = scope.strip().lower().lstrip(".")
        if not scope:
            return True
        name = record.name.lower()
        return name == scope or name.endswith(f".{scope}")

    def _merge(self, group: list[DiscoveryRecord]) -> DiscoveryRecord:
        """Merge one group of corroborating records into a single record."""
        primary = max(group, key=lambda record: self._confidence.record_confidence(record))
        merged_confidence = self._confidence.merged_confidence(group)
        tools = sorted({record.tool_id for record in group if record.tool_id})
        sources = sorted({record.source for record in group if record.source})
        details = dict(primary.details)
        details["tools"] = tools
        if sources:
            details["sources"] = sources
        merged_details = _merge_details(details, group)
        target_id = next((record.target_id for record in group if record.target_id), None)
        return DiscoveryRecord(
            kind=primary.kind,
            name=primary.name,
            tool_id=primary.tool_id,
            source=primary.source,
            confidence=merged_confidence,
            target_id=target_id,
            details=merged_details,
            observed_at=primary.observed_at,
            record_id=primary.record_id,
        )


def _merge_details(primary: dict[str, object], group: list[DiscoveryRecord]) -> dict[str, object]:
    """Fold list-valued detail fields from corroborating records into ``primary``."""
    merged = dict(primary)
    for record in group:
        for key, value in record.details.items():
            existing = merged.get(key)
            if isinstance(existing, list) and isinstance(value, list):
                merged[key] = _dedup(existing + list(value))
            elif key not in merged and value is not None:
                merged[key] = value
    return merged


def _dedup(items: list[object]) -> list[object]:
    """Return ``items`` with duplicates removed while preserving order."""
    seen: set[object] = set()
    result: list[object] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
