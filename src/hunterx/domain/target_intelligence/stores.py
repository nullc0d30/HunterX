# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Intelligence Stores.

Sprint 026. Port contracts and in-memory implementations for the durable stores
behind the intelligence layer: assets, immutable observations and evidence.
Stores are tenant/mission/target isolated and SQL-backed via the application
service; the in-memory variants power tests and ephemeral runs.
"""

from __future__ import annotations

import abc
from collections.abc import Iterator
from typing import Generic, TypeVar

from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceEvidence,
    Observation,
)
from hunterx.domain.topology.enums import EntityKind

T = TypeVar("T")


class TargetScopedStore(abc.ABC, Generic[T]):
    """Base contract for a target-scoped intelligence store.

    Every store enforces tenant/mission/target isolation: reads without an
    explicit target scope must never leak across targets.
    """

    @abc.abstractmethod
    def add(self, item: T) -> T:
        """Persist an item, returning the stored item."""

    @abc.abstractmethod
    def count(self, *, target_id: str = "", mission_id: str = "") -> int:
        """Return the number of stored items within an optional scope."""

    @abc.abstractmethod
    def clear(self) -> None:
        """Drop all items (test/teardown helper)."""


class AssetIntelligenceStore(TargetScopedStore[IntelligenceAsset]):
    """Store of canonical intelligence assets keyed by canonical asset key."""

    @abc.abstractmethod
    def upsert(self, asset: IntelligenceAsset) -> IntelligenceAsset:
        """Insert or refresh an asset by canonical key."""

    @abc.abstractmethod
    def get(self, key: str, *, include_deleted: bool = False) -> IntelligenceAsset | None:
        """Return an asset by canonical key or ``None``."""

    @abc.abstractmethod
    def list(
        self,
        *,
        target_id: str = "",
        mission_id: str = "",
        kind: EntityKind | str | None = None,
    ) -> list[IntelligenceAsset]:
        """Return assets within an optional scope, optionally filtered by kind."""


class ObservationStore(TargetScopedStore[Observation]):
    """Store of immutable observations.

    Observations are immutable: an observation is never mutated in place.
    Corrections are stored as new observations that supersede older ones.
    """

    @abc.abstractmethod
    def add(self, observation: Observation) -> Observation:
        """Persist an observation (immutable insert)."""

    @abc.abstractmethod
    def stream(self, *, target_id: str = "", mission_id: str = "") -> Iterator[Observation]:
        """Yield observations in batches within an optional scope."""

    @abc.abstractmethod
    def by_asset(self, asset_key: str, *, target_id: str = "") -> list[Observation]:
        """Return observations linked to an asset key."""

    @abc.abstractmethod
    def by_tool(self, tool: str, *, target_id: str = "") -> list[Observation]:
        """Return observations produced by a tool."""

    @abc.abstractmethod
    def dedup_key_exists(self, dedup_key: str, *, target_id: str) -> bool:
        """Return ``True`` when an observation with the dedup key already exists."""


class EvidenceStore(TargetScopedStore[IntelligenceEvidence]):
    """Store of evidence records (WHAT/WHERE/WHEN/HOW/SOURCE/WHY_TRUST)."""

    @abc.abstractmethod
    def get(self, evidence_id: str) -> IntelligenceEvidence | None:
        """Return an evidence record by id or ``None``."""

    @abc.abstractmethod
    def list(self, *, target_id: str = "", mission_id: str = "") -> list[IntelligenceEvidence]:
        """Return evidence records within an optional scope."""


# ==========================================================================
# In-memory implementations
# ==========================================================================


class InMemoryAssetIntelligenceStore(AssetIntelligenceStore):
    """Dict-backed asset store."""

    def __init__(self) -> None:
        self._assets: dict[str, IntelligenceAsset] = {}
        self._by_target: dict[str, set[str]] = {}

    def upsert(self, asset: IntelligenceAsset) -> IntelligenceAsset:
        """Insert or refresh an asset by canonical key."""
        prior = self._assets.get(asset.key)
        stored = prior if prior is not None else asset
        if prior is not None:
            import dataclasses

            stored = dataclasses.replace(
                prior,
                label=asset.label or prior.label,
                properties={**prior.properties, **asset.properties},
                confidence=max(prior.confidence, asset.confidence),
                in_scope=asset.in_scope and prior.in_scope,
                source=asset.source or prior.source,
                last_seen=asset.last_seen,
                parent_key=asset.parent_key or prior.parent_key,
                observed_by=tuple(dict.fromkeys((*prior.observed_by, *asset.observed_by))),
            )
        self._assets[asset.key] = stored
        self._by_target.setdefault(asset.target_id, set()).add(asset.key)
        return stored

    def get(self, key: str, *, include_deleted: bool = False) -> IntelligenceAsset | None:
        """Return an asset by canonical key or ``None``."""
        return self._assets.get(key)

    def list(self, *, target_id: str = "", mission_id: str = "", kind: EntityKind | str | None = None) -> list[IntelligenceAsset]:
        """Return assets within an optional scope, optionally filtered by kind."""
        assets = list(self._assets.values())
        if target_id:
            keys = self._by_target.get(target_id, set())
            assets = [asset for asset in assets if asset.key in keys]
        if mission_id:
            assets = [asset for asset in assets if asset.mission_id == mission_id]
        if kind is not None:
            expected = kind.value if isinstance(kind, EntityKind) else str(kind)
            assets = [asset for asset in assets if (asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)) == expected]
        return sorted(assets, key=lambda a: a.key)

    def add(self, item: IntelligenceAsset) -> IntelligenceAsset:
        """Persist an asset (alias of :meth:`upsert`)."""
        return self.upsert(item)

    def count(self, *, target_id: str = "", mission_id: str = "") -> int:
        """Return the number of stored assets within an optional scope."""
        return len(self.list(target_id=target_id, mission_id=mission_id))

    def clear(self) -> None:
        """Drop all assets."""
        self._assets.clear()
        self._by_target.clear()


class InMemoryObservationStore(ObservationStore):
    """List-backed immutable observation store with dedup checks."""

    def __init__(self) -> None:
        self._observations: dict[str, Observation] = {}
        self._dedup: dict[str, set[str]] = {}

    def add(self, observation: Observation) -> Observation:
        """Persist an observation (immutable insert)."""
        self._observations[observation.observation_id] = observation
        self._dedup.setdefault(observation.target_id, set()).add(observation.dedup_key)
        return observation

    def stream(self, *, target_id: str = "", mission_id: str = "") -> Iterator[Observation]:
        """Yield observations within an optional scope."""
        for observation in self._observations.values():
            if target_id and observation.target_id != target_id:
                continue
            if mission_id and observation.mission_id != mission_id:
                continue
            yield observation

    def by_asset(self, asset_key: str, *, target_id: str = "") -> list[Observation]:
        """Return observations linked to an asset key."""
        matched = [obs for obs in self._observations.values() if obs.asset_key == asset_key]
        if target_id:
            matched = [obs for obs in matched if obs.target_id == target_id]
        return sorted(matched, key=lambda o: o.timestamp)

    def by_tool(self, tool: str, *, target_id: str = "") -> list[Observation]:
        """Return observations produced by a tool."""
        matched = [obs for obs in self._observations.values() if obs.tool == tool]
        if target_id:
            matched = [obs for obs in matched if obs.target_id == target_id]
        return sorted(matched, key=lambda o: o.timestamp)

    def dedup_key_exists(self, dedup_key: str, *, target_id: str) -> bool:
        """Return ``True`` when an observation with the dedup key exists."""
        return dedup_key in self._dedup.get(target_id, set())

    def count(self, *, target_id: str = "", mission_id: str = "") -> int:
        """Return the number of stored observations within an optional scope."""
        matched = list(self._observations.values())
        if target_id:
            matched = [obs for obs in matched if obs.target_id == target_id]
        if mission_id:
            matched = [obs for obs in matched if obs.mission_id == mission_id]
        return len(matched)

    def clear(self) -> None:
        """Drop all observations."""
        self._observations.clear()
        self._dedup.clear()


class InMemoryEvidenceStore(EvidenceStore):
    """Dict-backed evidence store."""

    def __init__(self) -> None:
        self._evidence: dict[str, IntelligenceEvidence] = {}

    def add(self, item: IntelligenceEvidence) -> IntelligenceEvidence:
        """Persist an evidence record."""
        self._evidence[item.evidence_id] = item
        return item

    def get(self, evidence_id: str) -> IntelligenceEvidence | None:
        """Return an evidence record by id or ``None``."""
        return self._evidence.get(evidence_id)

    def list(self, *, target_id: str = "", mission_id: str = "") -> list[IntelligenceEvidence]:
        """Return evidence records within an optional scope."""
        matched = list(self._evidence.values())
        if target_id:
            matched = [e for e in matched if e.target_id == target_id]
        if mission_id:
            matched = [e for e in matched if e.mission_id == mission_id]
        return sorted(matched, key=lambda e: e.created_at)

    def count(self, *, target_id: str = "", mission_id: str = "") -> int:
        """Return the number of stored evidence records within an optional scope."""
        return len(self.list(target_id=target_id, mission_id=mission_id))

    def clear(self) -> None:
        """Drop all evidence records."""
        self._evidence.clear()


__all__ = [
    "AssetIntelligenceStore",
    "EvidenceStore",
    "InMemoryAssetIntelligenceStore",
    "InMemoryEvidenceStore",
    "InMemoryObservationStore",
    "ObservationStore",
    "TargetScopedStore",
]
