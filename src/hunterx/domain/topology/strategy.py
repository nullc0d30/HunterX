# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Topology build strategy.

Configures a topology build run: mode, scope policy, which relationship types
to derive, which tools to execute, confidence and staleness thresholds and
which analysis features to enable. The builder derives a strategy from a target
and caller parameters with sensible defaults.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.topology.enums import RelationshipType, TopologyMode
from hunterx.domain.topology.scope import TopologyScopePolicy


@dataclass(slots=True)
class TopologyStrategy:
    """Configuration for a single topology build run.

    Attributes:
        target_key: canonical key of the build target (a domain).
        mode: build mode (full recompute or incremental refresh).
        scope: scope policy governing the build.
        relationship_types: subset of relationship types to derive/keep.
        tools: tool ids to execute for route-level observations.
        tool_parameters: per-tool parameter mapping.
        confidence_threshold: drop edges below this confidence.
        stale_days: staleness horizon for analysis.
        include_shared: derive SHARES_* relationships.
        include_routes: derive ROUTES_TO edges from tools.
        include_discovered: derive DISCOVERED_BY attribution edges.
        max_relationships: safety cap on persisted edges (0 = unbounded).

    """

    target_key: str
    mode: str = TopologyMode.FULL
    scope: TopologyScopePolicy = field(default_factory=TopologyScopePolicy)
    relationship_types: set[str] = field(default_factory=set)
    tools: list[str] = field(default_factory=list)
    tool_parameters: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    confidence_threshold: float = 0.5
    stale_days: float = 90.0
    include_shared: bool = True
    include_routes: bool = True
    include_discovered: bool = True
    max_relationships: int = 0

    def allows(self, rel_type: RelationshipType | str) -> bool:
        """Return ``True`` when the relationship type is enabled."""
        value = rel_type.value if isinstance(rel_type, RelationshipType) else str(rel_type)
        if not self.relationship_types:
            return True
        return value in self.relationship_types


class TopologyStrategyBuilder:
    """Build a :class:`TopologyStrategy` from run inputs."""

    #: Default enabled relationship types when none are specified.
    DEFAULT_TYPES: frozenset[str] = frozenset(
        rt.value for rt in RelationshipType if not rt.value.startswith("shares_")
    )

    def build(
        self,
        *,
        target_key: str,
        mode: str | TopologyMode = TopologyMode.FULL,
        scope: TopologyScopePolicy | None = None,
        relationship_types: Sequence[str] | None = None,
        tools: Sequence[str] | None = None,
        tool_parameters: Mapping[str, Mapping[str, Any]] | None = None,
        confidence_threshold: float = 0.5,
        stale_days: float = 90.0,
        include_shared: bool = True,
        include_routes: bool = True,
        include_discovered: bool = True,
        max_relationships: int = 0,
    ) -> TopologyStrategy:
        """Construct a strategy, normalizing inputs to valid enums."""
        mode_value = TopologyMode(mode if isinstance(mode, str) else mode.value).value
        types = set(relationship_types or self.DEFAULT_TYPES)
        if include_shared:
            types.update(rt.value for rt in RelationshipType if rt.value.startswith("shares_"))
        return TopologyStrategy(
            target_key=target_key,
            mode=mode_value,
            scope=scope or TopologyScopePolicy(),
            relationship_types=types,
            tools=list(tools or []),
            tool_parameters=dict(tool_parameters or {}),
            confidence_threshold=max(0.0, min(1.0, confidence_threshold)),
            stale_days=stale_days,
            include_shared=include_shared,
            include_routes=include_routes,
            include_discovered=include_discovered,
            max_relationships=max(0, max_relationships),
        )
