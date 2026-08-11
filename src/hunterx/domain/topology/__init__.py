# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Network mapping & attack-surface topology domain.

Pure-domain capability that transforms canonical TIDB entities into a unified,
queryable attack-surface topology. The domain is deliberately free of I/O: it
defines the entity/relationship model, deterministic derivation and resolution
rules, correlation and conflict handling, temporal history, analysis, path
finding, graph views and scope enforcement. The application layer bridges these
to the TIDB (system of record) and the Tool Integration SDK.
"""

from __future__ import annotations

from hunterx.domain.topology.analysis import TopologyAnalyzer
from hunterx.domain.topology.confidence import TopologyConfidenceEngine
from hunterx.domain.topology.conflicts import TopologyConflictResolver
from hunterx.domain.topology.correlator import TopologyCorrelator
from hunterx.domain.topology.deriver import RelationshipDeriver
from hunterx.domain.topology.enums import (
    ChangeType,
    ClusterType,
    ConflictType,
    EntityKind,
    RelationshipType,
    TopologyMode,
    TopologyStatus,
)
from hunterx.domain.topology.graph import TopologyGraph
from hunterx.domain.topology.history import TopologyHistory
from hunterx.domain.topology.models import (
    GraphRelationship,
    RelationshipObservation,
    TopologyAnalysis,
    TopologyBatch,
    TopologyChange,
    TopologyCluster,
    TopologyConflict,
    TopologyEntity,
    TopologyExecutionSummary,
    TopologySourceData,
    TopologyTarget,
)
from hunterx.domain.topology.normalizer import TopologyNormalizer
from hunterx.domain.topology.paths import TopologyPathFinder
from hunterx.domain.topology.resolver import EntityResolver
from hunterx.domain.topology.scope import (
    ScopeDecision,
    TopologyScopeEnforcer,
    TopologyScopePolicy,
)
from hunterx.domain.topology.strategy import TopologyStrategy, TopologyStrategyBuilder
from hunterx.domain.topology.validator import TopologyValidator
from hunterx.domain.topology.views import TopologyViewBuilder

__all__ = [
    "ChangeType",
    "ClusterType",
    "ConflictType",
    "EntityKind",
    "EntityResolver",
    "GraphRelationship",
    "RelationshipDeriver",
    "RelationshipObservation",
    "RelationshipType",
    "ScopeDecision",
    "TopologyAnalysis",
    "TopologyAnalyzer",
    "TopologyBatch",
    "TopologyChange",
    "TopologyCluster",
    "TopologyConfidenceEngine",
    "TopologyConflict",
    "TopologyConflictResolver",
    "TopologyCorrelator",
    "TopologyEntity",
    "TopologyExecutionSummary",
    "TopologyGraph",
    "TopologyHistory",
    "TopologyMode",
    "TopologyNormalizer",
    "TopologyPathFinder",
    "TopologyScopeEnforcer",
    "TopologyScopePolicy",
    "TopologySourceData",
    "TopologyStatus",
    "TopologyStrategy",
    "TopologyStrategyBuilder",
    "TopologyTarget",
    "TopologyValidator",
    "TopologyViewBuilder",
]
