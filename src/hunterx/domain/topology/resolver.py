# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology entity resolver.

Maps raw entity values to canonical, de-duplicated :class:`TopologyEntity`
nodes. The resolver keeps a per-run cache so identical references always yield
the same node (deterministic correlation); the cache is never shared between
runs to avoid stale state.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.topology.enums import EntityKind
from hunterx.domain.topology.normalizer import TopologyNormalizer


class EntityResolver:
    """Resolve and cache canonical topology nodes."""

    def __init__(self, normalizer: TopologyNormalizer | None = None) -> None:
        self._normalizer = normalizer or TopologyNormalizer()
        self._nodes: dict[str, Any] = {}

    @property
    def normalizer(self) -> TopologyNormalizer:
        """Return the normalizer backing this resolver."""
        return self._normalizer

    def resolve(
        self,
        kind: EntityKind | str,
        name: str,
        *,
        entity_id: str | None = None,
        label: str = "",
    ) -> Any:
        """Return the canonical node for ``kind``/``name`` (cached).

        Re-resolving an already-seen entity returns the existing node so a
        given asset always has exactly one representation in a build.
        """
        from hunterx.domain.topology.models import TopologyEntity

        kind_enum = EntityKind(kind if isinstance(kind, str) else kind.value)
        canonical = self._normalizer.normalize(kind_enum, name)
        key = f"{kind_enum.value}:{canonical}"
        existing = self._nodes.get(key)
        if existing is not None:
            if entity_id is not None and existing.entity_id is None:
                return TopologyEntity(kind=kind_enum, name=canonical, key=key, entity_id=entity_id, label=label)
            return existing
        node = TopologyEntity(kind=kind_enum, name=canonical, key=key, entity_id=entity_id, label=label)
        self._nodes[key] = node
        return node

    def resolve_key(self, key: str, *, entity_id: str | None = None) -> Any:
        """Resolve a pre-built ``kind:name`` key to a canonical node."""
        kind, _, name = key.partition(":")
        if not kind or not name:
            raise ValueError(f"invalid entity key '{key}'")
        return self.resolve(kind, name, entity_id=entity_id)

    def known_keys(self) -> set[str]:
        """Return every canonical key resolved so far."""
        return set(self._nodes)

    def clear(self) -> None:
        """Drop all cached nodes (start a fresh run)."""
        self._nodes.clear()
