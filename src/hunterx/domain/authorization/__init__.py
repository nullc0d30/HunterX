# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization & access-control intelligence domain.

Pure-domain contracts and deterministic analysis for the Wave 10
authorization intelligence capability: canonical observation models, the
static/observable detection engine, classification, confidence scoring,
correlation, conflict resolution, historical diffing, scope enforcement and
collection strategy. No I/O and no execution in this package.

Responsibilities:
- canonical evidence-backed models for subjects, roles, groups, permissions,
  scopes, claims, policies, resources, actions, identifiers, ownership,
  tenants, admin surfaces, function/object/field-level access control,
  frontend/backend logic, API/GraphQL/WebSocket/service authorization,
  decision indicators and mass-assignment fields.
- deterministic analyzer, classifier, confidence engine, correlator, history
  comparator, scope enforcer, strategy builder and validator.

Dependencies:
- ``hunterx.domain.recon.models`` for the execution posture.
- ``hunterx.shared`` for identifiers, timestamps and secret masking.

Extension points:
- add a record type to :mod:`hunterx.domain.authorization.models` and mirror
  it in the analyzer, correlator/history subject-type maps, the TIDB entity
  module and the application service.
"""

from __future__ import annotations

from hunterx.domain.authorization.analyzer import (
    AuthorizationAnalysis,
    AuthorizationAnalyzer,
)
from hunterx.domain.authorization.classification import AuthorizationClassifier
from hunterx.domain.authorization.confidence import (
    AuthorizationConfidenceEngine,
    AuthorizationConfidencePolicy,
)
from hunterx.domain.authorization.correlator import (
    AuthorizationCorrelationResult,
    AuthorizationCorrelator,
)
from hunterx.domain.authorization.history import (
    AuthorizationHistory,
    AuthorizationHistoryComparison,
)
from hunterx.domain.authorization.models import (
    FINDINGS_KEY,
    ActionKind,
    AdminSurfaceKind,
    AuthorizationBatch,
    AuthorizationChange,
    AuthorizationConflict,
    AuthorizationExecutionSummary,
    AuthorizationInput,
    AuthorizationTarget,
    AuthzAccessControlObservation,
    AuthzActionObservation,
    AuthzAdminSurfaceObservation,
    AuthzApiCorrelationObservation,
    AuthzBackendObservation,
    AuthzClaimObservation,
    AuthzDecisionObservation,
    AuthzEvidence,
    AuthzEvidenceType,
    AuthzFieldLevelObservation,
    AuthzFrontendObservation,
    AuthzFunctionLevelObservation,
    AuthzGraphQLObservation,
    AuthzGroupObservation,
    AuthzMassAssignmentObservation,
    AuthzObjectLevelObservation,
    AuthzObservation,
    AuthzObservationKind,
    AuthzOwnershipObservation,
    AuthzPermissionObservation,
    AuthzPolicyObservation,
    AuthzResourceIdentifierObservation,
    AuthzResourceObservation,
    AuthzRoleObservation,
    AuthzScopeObservation,
    AuthzServiceObservation,
    AuthzSubjectObservation,
    AuthzTenantObservation,
    AuthzWebSocketObservation,
    ChangeType,
    DecisionKind,
    EvidenceStrength,
    IdentifierKind,
    OwnershipKind,
    PolicyModelKind,
    ResourceKind,
    SubjectKind,
    TenantKind,
    infer_asset_type,
    make_evidence,
    observations_from_payload,
    origin_of,
    record_to_dict,
    record_type_of,
)
from hunterx.domain.authorization.scope import (
    AuthorizationScopeEnforcer,
    AuthorizationScopePolicy,
    ScopeDecision,
)
from hunterx.domain.authorization.strategy import (
    AuthorizationStrategy,
    AuthorizationStrategyBuilder,
)
from hunterx.domain.authorization.validator import AuthorizationValidator

__all__ = [
    "ActionKind",
    "AdminSurfaceKind",
    "AuthzAccessControlObservation",
    "AuthzActionObservation",
    "AuthzAdminSurfaceObservation",
    "AuthzApiCorrelationObservation",
    "AuthzBackendObservation",
    "AuthzClaimObservation",
    "AuthzDecisionObservation",
    "AuthzEvidence",
    "AuthzEvidenceType",
    "AuthzFieldLevelObservation",
    "AuthzFrontendObservation",
    "AuthzFunctionLevelObservation",
    "AuthzGraphQLObservation",
    "AuthzGroupObservation",
    "AuthzMassAssignmentObservation",
    "AuthzObjectLevelObservation",
    "AuthzObservation",
    "AuthzObservationKind",
    "AuthzOwnershipObservation",
    "AuthzPermissionObservation",
    "AuthzPolicyObservation",
    "AuthzResourceIdentifierObservation",
    "AuthzResourceObservation",
    "AuthzRoleObservation",
    "AuthzScopeObservation",
    "AuthzServiceObservation",
    "AuthzSubjectObservation",
    "AuthzTenantObservation",
    "AuthzWebSocketObservation",
    "AuthorizationAnalysis",
    "AuthorizationAnalyzer",
    "AuthorizationBatch",
    "AuthorizationChange",
    "AuthorizationClassifier",
    "AuthorizationConfidenceEngine",
    "AuthorizationConfidencePolicy",
    "AuthorizationConflict",
    "AuthorizationCorrelationResult",
    "AuthorizationCorrelator",
    "AuthorizationExecutionSummary",
    "AuthorizationHistory",
    "AuthorizationHistoryComparison",
    "AuthorizationInput",
    "AuthorizationScopeEnforcer",
    "AuthorizationScopePolicy",
    "AuthorizationStrategy",
    "AuthorizationStrategyBuilder",
    "AuthorizationTarget",
    "AuthorizationValidator",
    "ChangeType",
    "DecisionKind",
    "EvidenceStrength",
    "FINDINGS_KEY",
    "IdentifierKind",
    "OwnershipKind",
    "PolicyModelKind",
    "ResourceKind",
    "ScopeDecision",
    "SubjectKind",
    "TenantKind",
    "infer_asset_type",
    "make_evidence",
    "observations_from_payload",
    "origin_of",
    "record_to_dict",
    "record_type_of",
]
