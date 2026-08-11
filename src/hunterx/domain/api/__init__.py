# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API intelligence domain package.

Pure-domain building blocks for the API Discovery & API Attack-Surface
Intelligence capability: canonical models, classification, scope enforcement,
confidence scoring, correlation, conflict resolution, historical comparison,
collection strategy, validation and the in-process spec parsers (OpenAPI,
GraphQL, WebSocket, SOAP, Postman and web/JS hint fold-in).
"""

from __future__ import annotations

from hunterx.domain.api.classification import ApiClassifier, Classification
from hunterx.domain.api.confidence import ApiConfidenceEngine
from hunterx.domain.api.conflicts import ApiConflictResolver
from hunterx.domain.api.correlator import ApiCorrelator, CorrelationResult
from hunterx.domain.api.history import ApiHistory, ApiHistoryComparison
from hunterx.domain.api.models import (
    FINDINGS_KEY,
    ApiAuthObservation,
    ApiBatch,
    ApiChange,
    ApiConflict,
    ApiEvidence,
    ApiExecutionSummary,
    ApiFilterObservation,
    APIHostObservation,
    ApiKind,
    ApiOperationObservation,
    ApiPaginationObservation,
    ApiParameterObservation,
    ApiRateLimitObservation,
    APISpecObservation,
    ApiTarget,
    EvidenceStrength,
    EvidenceType,
    make_host_observation,
    make_operation_observation,
    normalize_path,
    observations_from_payload,
    operation_hash,
    origin_of,
)
from hunterx.domain.api.scope import ApiScopeEnforcer, ApiScopePolicy, ScopeDecision
from hunterx.domain.api.strategy import ApiStrategy, ApiStrategyBuilder
from hunterx.domain.api.validator import ApiValidator

__all__ = [
    "APISpecObservation",
    "APIHostObservation",
    "ApiAuthObservation",
    "ApiBatch",
    "ApiChange",
    "ApiClassifier",
    "ApiConflict",
    "ApiConflictResolver",
    "ApiConfidenceEngine",
    "ApiCorrelator",
    "ApiExecutionSummary",
    "ApiFilterObservation",
    "ApiHistory",
    "ApiHistoryComparison",
    "ApiKind",
    "ApiOperationObservation",
    "ApiPaginationObservation",
    "ApiParameterObservation",
    "ApiRateLimitObservation",
    "ApiScopeEnforcer",
    "ApiScopePolicy",
    "ApiStrategy",
    "ApiStrategyBuilder",
    "ApiTarget",
    "ApiValidator",
    "ApiEvidence",
    "Classification",
    "CorrelationResult",
    "EvidenceStrength",
    "EvidenceType",
    "FINDINGS_KEY",
    "ScopeDecision",
    "make_host_observation",
    "make_operation_observation",
    "normalize_path",
    "observations_from_payload",
    "operation_hash",
    "origin_of",
]
