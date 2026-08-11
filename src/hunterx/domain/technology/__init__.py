# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology fingerprinting domain package.

Pure, framework-free contracts and logic for the technology intelligence
capability: technology observation models, the canonical taxonomy, name
normalization and resolution, version intelligence, signature-based in-process
detection, confidence scoring, scope enforcement, correlation/conflict
handling, historical comparison and collection strategy.

The package depends only on the shared primitives and the recon domain for the
execution mode enum — no I/O, no tool calls and no persistence here.
"""

from hunterx.domain.technology.confidence import (
    TechnologyConfidenceEngine,
    TechnologyConfidencePolicy,
)
from hunterx.domain.technology.conflicts import ConflictResolution, TechnologyConflictResolver
from hunterx.domain.technology.correlator import (
    TechnologyCorrelationResult,
    TechnologyCorrelator,
)
from hunterx.domain.technology.detector import HttpEvidence, SignatureDetector
from hunterx.domain.technology.history import (
    TechnologyHistory,
    TechnologyHistoryComparison,
)
from hunterx.domain.technology.models import (
    ASSET_DOMAIN,
    ASSET_HOSTNAME,
    ASSET_IP,
    ASSET_SERVICE,
    ASSET_URL,
    EvidenceStrength,
    EvidenceType,
    TechChange,
    TechConflict,
    TechExecutionSummary,
    TechnologyBatch,
    TechnologyCategory,
    TechnologyEvidence,
    TechnologyFamily,
    TechnologyObservation,
    TechTarget,
    VersionConfidence,
    VersionSpec,
    infer_asset_type,
    make_observation,
    observations_from_payload,
)
from hunterx.domain.technology.normalizer import NormalizedName, TechnologyNormalizer
from hunterx.domain.technology.resolver import Resolution, TechnologyResolver
from hunterx.domain.technology.scope import (
    ScopeDecision,
    TechnologyScopeEnforcer,
    TechnologyScopePolicy,
)
from hunterx.domain.technology.signatures import (
    SIGNATURES,
    SignatureMatchMode,
    TechSignature,
    all_signatures,
    signatures_for,
)
from hunterx.domain.technology.strategy import TechStrategy, TechStrategyBuilder
from hunterx.domain.technology.taxonomy import TECHNOLOGY_CATALOG, TechDefinition, catalog_by_name
from hunterx.domain.technology.validator import (
    TechnologyValidationResult,
    TechnologyValidator,
    ValidationIssue,
)
from hunterx.domain.technology.version import VersionExtraction, VersionResolver

__all__ = [
    "ASSET_DOMAIN",
    "ASSET_HOSTNAME",
    "ASSET_IP",
    "ASSET_SERVICE",
    "ASSET_URL",
    "ConflictResolution",
    "EvidenceStrength",
    "EvidenceType",
    "HttpEvidence",
    "NormalizedName",
    "Resolution",
    "SIGNATURES",
    "ScopeDecision",
    "SignatureDetector",
    "SignatureMatchMode",
    "TechChange",
    "TechConflict",
    "TechDefinition",
    "TechExecutionSummary",
    "TechSignature",
    "TechStrategy",
    "TechStrategyBuilder",
    "TechTarget",
    "TECHNOLOGY_CATALOG",
    "TechnologyBatch",
    "TechnologyCategory",
    "TechnologyConfidenceEngine",
    "TechnologyConfidencePolicy",
    "TechnologyConflictResolver",
    "TechnologyCorrelationResult",
    "TechnologyCorrelator",
    "TechnologyEvidence",
    "TechnologyFamily",
    "TechnologyHistory",
    "TechnologyHistoryComparison",
    "TechnologyNormalizer",
    "TechnologyObservation",
    "TechnologyScopeEnforcer",
    "TechnologyScopePolicy",
    "TechnologyValidationResult",
    "TechnologyValidator",
    "TechnologyResolver",
    "ValidationIssue",
    "VersionConfidence",
    "VersionExtraction",
    "VersionResolver",
    "VersionSpec",
    "all_signatures",
    "catalog_by_name",
    "infer_asset_type",
    "make_observation",
    "observations_from_payload",
    "signatures_for",
]
