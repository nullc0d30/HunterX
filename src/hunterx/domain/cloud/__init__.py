# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS attack-surface intelligence domain.

Pure-domain, I/O-free contracts and algorithms for the Wave 11 cloud & SaaS
intelligence capability: canonical observation models, the evidence-based
provider detection registry, classification, deterministic confidence scoring,
scope enforcement, collection strategy, correlation, conflict resolution,
historical diffing, validation, sensitive-data redaction and the in-process
analyzer.
"""

from __future__ import annotations

from hunterx.domain.cloud.analyzer import CloudAnalyzer
from hunterx.domain.cloud.classification import CloudClassifier
from hunterx.domain.cloud.confidence import CloudConfidenceEngine, CloudConfidencePolicy
from hunterx.domain.cloud.conflicts import CloudConflictResolver, CloudConflictResult
from hunterx.domain.cloud.correlator import CloudCorrelationResult, CloudCorrelator
from hunterx.domain.cloud.history import CloudHistory, CloudHistoryComparison
from hunterx.domain.cloud.models import (
    FINDINGS_KEY,
    ApiGatewayResourceObservation,
    CdnResourceObservation,
    CiCdResourceObservation,
    CloudAccountObservation,
    CloudAnalysis,
    CloudBatch,
    CloudChange,
    CloudConflict,
    CloudDependencyObservation,
    CloudEndpointObservation,
    CloudEnvironmentObservation,
    CloudEvidence,
    CloudExecutionSummary,
    CloudExposureObservation,
    CloudIdentityObservation,
    CloudInput,
    CloudIntegrationObservation,
    CloudObservation,
    CloudPermissionObservation,
    CloudProviderObservation,
    CloudRegionObservation,
    CloudResourceObservation,
    CloudRoleObservation,
    CloudServiceObservation,
    CloudTarget,
    ComputeResourceObservation,
    ContainerResourceObservation,
    DatabaseResourceObservation,
    EvidenceStrength,
    EvidenceType,
    KubernetesResourceObservation,
    LoadBalancerResourceObservation,
    MessageInfrastructureObservation,
    SaaSApplicationObservation,
    SaaSIntegrationObservation,
    SaaSProviderObservation,
    SecretManagementObservation,
    StorageResourceObservation,
    WebhookObservation,
    infer_asset_type,
    make_evidence,
    observations_from_payload,
    origin_of,
    record_from_dict,
    record_to_dict,
    record_type_of,
)
from hunterx.domain.cloud.providers import ProviderCatalog, ProviderMatch, ProviderSignature
from hunterx.domain.cloud.redaction import fingerprint, redact_indicators, safe_context
from hunterx.domain.cloud.scope import (
    CloudScopeEnforcer,
    CloudScopePolicy,
    ScopeDecision,
)
from hunterx.domain.cloud.strategy import CloudStrategy, CloudStrategyBuilder
from hunterx.domain.cloud.validator import (
    CloudValidationResult,
    CloudValidator,
    ValidationIssue,
)

__all__ = [
    "ApiGatewayResourceObservation",
    "CdnResourceObservation",
    "CiCdResourceObservation",
    "CloudAccountObservation",
    "CloudAnalysis",
    "CloudAnalyzer",
    "CloudBatch",
    "CloudChange",
    "CloudClassifier",
    "CloudConfidenceEngine",
    "CloudConfidencePolicy",
    "CloudConflict",
    "CloudConflictResolver",
    "CloudConflictResult",
    "CloudCorrelationResult",
    "CloudCorrelator",
    "CloudDependencyObservation",
    "CloudEndpointObservation",
    "CloudEnvironmentObservation",
    "CloudEvidence",
    "CloudExecutionSummary",
    "CloudExposureObservation",
    "CloudHistory",
    "CloudHistoryComparison",
    "CloudIdentityObservation",
    "CloudInput",
    "CloudIntegrationObservation",
    "CloudObservation",
    "CloudPermissionObservation",
    "CloudProviderObservation",
    "CloudRegionObservation",
    "CloudResourceObservation",
    "CloudRoleObservation",
    "CloudScopeEnforcer",
    "CloudScopePolicy",
    "CloudServiceObservation",
    "CloudStrategy",
    "CloudStrategyBuilder",
    "CloudTarget",
    "CloudValidationResult",
    "CloudValidator",
    "ComputeResourceObservation",
    "ContainerResourceObservation",
    "DatabaseResourceObservation",
    "EvidenceStrength",
    "EvidenceType",
    "FINDINGS_KEY",
    "KubernetesResourceObservation",
    "LoadBalancerResourceObservation",
    "MessageInfrastructureObservation",
    "ProviderCatalog",
    "ProviderMatch",
    "ProviderSignature",
    "SaaSApplicationObservation",
    "SaaSIntegrationObservation",
    "SaaSProviderObservation",
    "ScopeDecision",
    "SecretManagementObservation",
    "StorageResourceObservation",
    "ValidationIssue",
    "WebhookObservation",
    "fingerprint",
    "infer_asset_type",
    "make_evidence",
    "observations_from_payload",
    "origin_of",
    "record_from_dict",
    "record_to_dict",
    "record_type_of",
    "redact_indicators",
    "safe_context",
]
