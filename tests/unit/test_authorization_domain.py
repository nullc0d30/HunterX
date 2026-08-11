# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authorization intelligence domain contracts.

Exercises the pure domain layer: canonical models, serialization round-trips,
classification, confidence scoring, correlation, conflict detection, history
diffing, scope enforcement, strategy and validation.
"""

from __future__ import annotations

from hunterx.domain.authorization.classification import AuthorizationClassifier
from hunterx.domain.authorization.confidence import AuthorizationConfidenceEngine
from hunterx.domain.authorization.correlator import AuthorizationCorrelator
from hunterx.domain.authorization.history import AuthorizationHistory
from hunterx.domain.authorization.models import (
    FINDINGS_KEY,
    AdminSurfaceKind,
    AuthzAdminSurfaceObservation,
    AuthzEvidence,
    AuthzPermissionObservation,
    AuthzResourceObservation,
    AuthzRoleObservation,
    DecisionKind,
    EvidenceStrength,
    make_evidence,
    observations_from_payload,
    origin_of,
    record_from_dict,
    record_to_dict,
)
from hunterx.domain.authorization.scope import (
    AuthorizationScopeEnforcer,
    AuthorizationScopePolicy,
)
from hunterx.domain.authorization.strategy import AuthorizationStrategyBuilder
from hunterx.domain.authorization.validator import AuthorizationValidator
from hunterx.domain.recon.models import ReconMode


class TestModels:
    def test_origin_of(self) -> None:
        assert origin_of("https://example.com/path?q=1") == "https://example.com"
        assert origin_of("not-a-url") == ""

    def test_serialization_roundtrip(self) -> None:
        resource = AuthzResourceObservation(
            origin="https://example.com",
            name="users",
            resource_kind="user",
            indicators=("url-pattern:resource:users",),
            confidence=0.7,
            evidence=(make_evidence(EvidenceStrength.STRONG, "https://example.com/api/users"),),
        )
        payload = record_to_dict(resource)
        assert payload["type"] == "resource"
        restored = record_from_dict(AuthzResourceObservation, payload)
        assert restored == resource

    def test_observations_from_payload_dispatch(self) -> None:
        resource = AuthzResourceObservation(origin="o", name="users")
        role = AuthzRoleObservation(origin="o", name="admin")
        payload = {FINDINGS_KEY: [record_to_dict(resource), record_to_dict(role)]}
        records = observations_from_payload(payload)
        assert len(records) == 2
        assert isinstance(records[0], AuthzResourceObservation)
        assert isinstance(records[1], AuthzRoleObservation)

    def test_observations_from_payload_ignores_unknown_types(self) -> None:
        payload = {FINDINGS_KEY: [{"type": "not-a-record", "origin": "x"}]}
        assert observations_from_payload(payload) == []

    def test_evidence_coercion(self) -> None:
        evidence = AuthzEvidence(evidence_type="api-operation", value="  x  ", strength="strong")
        assert str(evidence.evidence_type) == "api-operation"
        assert evidence.value == "x"
        assert str(evidence.strength) == "strong"

    def test_permission_key_and_parts(self) -> None:
        permission = AuthzPermissionObservation(origin="https://example.com", name="users.read")
        assert permission.key() == "permission:https://example.com|users.read"
        assert permission.action == ""
        assert permission.resource == ""


class TestClassification:
    def test_admin_surface_classified(self) -> None:
        classifier = AuthorizationClassifier()
        surface = AuthzAdminSurfaceObservation(
            url="https://example.com/admin",
            origin="https://example.com",
            surface_kind=AdminSurfaceKind.UNKNOWN,
        )
        classified = classifier.classify_admin_surface(surface)
        assert classified.surface_kind is AdminSurfaceKind.ADMIN_UI

    def test_resource_classified(self) -> None:
        classifier = AuthorizationClassifier()
        resource = AuthzResourceObservation(origin="o", name="projects", resource_kind="unknown")
        classified = classifier.classify_resource(resource)
        assert str(classified.resource_kind) == "project"

    def test_decision_classified(self) -> None:
        classifier = AuthorizationClassifier()
        assert classifier.classify_decision(status_code=403) is DecisionKind.DENY
        assert classifier.classify_decision(status_code=200) is DecisionKind.ALLOW
        assert classifier.classify_decision(documented="conditional") is DecisionKind.CONDITIONAL
        assert classifier.classify_decision() is DecisionKind.UNKNOWN


class TestConfidence:
    def test_observation_confidence_is_deterministic(self) -> None:
        engine = AuthorizationConfidenceEngine()
        role = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3)
        score = engine.observation_confidence(role)
        assert 0.0 <= score <= 1.0
        assert score == engine.observation_confidence(role)

    def test_merged_confidence_boost(self) -> None:
        engine = AuthorizationConfidenceEngine()
        role_a = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3, source="authorization")
        role_b = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3, source="api")
        merged = engine.merged_confidence([role_a, role_b])
        single = engine.merged_confidence([role_a])
        assert merged >= single

    def test_conflict_discount(self) -> None:
        engine = AuthorizationConfidenceEngine()
        role = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3)
        conflicted = engine.merged_confidence([role], conflicted=True)
        plain = engine.merged_confidence([role])
        assert conflicted < plain


class TestCorrelation:
    def test_correlation_merges_duplicates(self) -> None:
        correlator = AuthorizationCorrelator()
        role_a = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3, source="authorization")
        role_b = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.5, source="api")
        result = correlator.correlate([role_a, role_b])
        assert len(result.records) == 1
        assert result.merged == 1

    def test_correlation_preserves_conflict(self) -> None:
        correlator = AuthorizationCorrelator()
        permission_a = AuthzPermissionObservation(
            origin="https://example.com",
            name="users.write",
            action="users",
            resource="write",
            confidence=0.4,
            source="authorization",
        )
        permission_b = AuthzPermissionObservation(
            origin="https://example.com",
            name="users.write",
            action="users",
            resource="read",
            confidence=0.4,
            source="api",
        )
        result = correlator.correlate([permission_a, permission_b])
        assert result.conflicts
        assert result.conflicts[0].subject_type == "permission"

    def test_correlation_scopes_out(self) -> None:
        correlator = AuthorizationCorrelator(
            scope=AuthorizationScopePolicy(roots=frozenset({"example.com"}))
        )
        role = AuthzRoleObservation(origin="https://evil.com", name="admin")
        result = correlator.correlate([role])
        assert result.scoped_out == 1
        assert result.records == ()


class TestHistory:
    def test_history_add_remove_change(self) -> None:
        history = AuthorizationHistory()
        historical_admin = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3, custom=False)
        historical_removed = AuthzRoleObservation(origin="https://example.com", name="legacy", confidence=0.3, custom=False)
        added_viewer = AuthzRoleObservation(origin="https://example.com", name="viewer", confidence=0.3, custom=True)
        changed_admin = AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.9, custom=True)
        comparison = history.compare([historical_admin, historical_removed], [added_viewer, changed_admin])
        types = {change.change_type for change in comparison.changes}
        assert types == {"removed", "added", "changed"}

    def test_history_identical_snapshots_no_changes(self) -> None:
        history = AuthorizationHistory()
        records = [AuthzRoleObservation(origin="https://example.com", name="admin", confidence=0.3)]
        comparison = history.compare(records, records)
        assert comparison.changes == ()
        assert comparison.unchanged == 1


class TestScope:
    def test_allows_root_and_subdomain(self) -> None:
        enforcer = AuthorizationScopeEnforcer(AuthorizationScopePolicy(roots=frozenset({"example.com"})))
        assert enforcer.allows_name("example.com").allowed
        assert enforcer.allows_name("sub.example.com").allowed
        assert not enforcer.allows_name("evil.com").allowed

    def test_excludes(self) -> None:
        enforcer = AuthorizationScopeEnforcer(
            AuthorizationScopePolicy(roots=frozenset({"example.com"}), excludes=frozenset({"admin.example.com"}))
        )
        assert not enforcer.allows_name("admin.example.com").allowed

    def test_observation_origin_checked(self) -> None:
        enforcer = AuthorizationScopeEnforcer(AuthorizationScopePolicy(roots=frozenset({"example.com"})))
        role = AuthzRoleObservation(origin="https://external.com", name="admin")
        assert not enforcer.allows_observation(role).allowed


class TestStrategy:
    def test_build_defaults(self) -> None:
        builder = AuthorizationStrategyBuilder()
        strategy = builder.build("https://example.com/api")
        assert strategy.target == "https://example.com/api"
        assert strategy.mode is ReconMode.HYBRID
        assert strategy.include_frontend is True
        assert strategy.include_api is True

    def test_tools_for_mode(self) -> None:
        builder = AuthorizationStrategyBuilder()
        tools = builder.tools_for(ReconMode.PASSIVE)
        assert tools == ("authorization-analysis",)


class TestValidator:
    def test_validates_origin_and_confidence(self) -> None:
        validator = AuthorizationValidator()
        good = AuthzResourceObservation(origin="https://example.com", name="users", confidence=0.4)
        assert validator.validate(good).valid
        bad = AuthzResourceObservation(origin="", name="users", confidence=0.4)
        assert not validator.validate(bad).valid
        assert validator.validate(bad).issues[0].code == "missing-origin"
