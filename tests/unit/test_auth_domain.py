# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the authentication intelligence domain contracts.

Exercises the pure domain layer: canonical models, serialization round-trips,
classification, confidence scoring, correlation, conflict detection, history
diffing, scope enforcement, strategy and validation.
"""

from __future__ import annotations

from hunterx.domain.auth.classification import AuthClassifier
from hunterx.domain.auth.confidence import AuthConfidenceEngine
from hunterx.domain.auth.correlator import AuthCorrelator
from hunterx.domain.auth.history import AuthHistory
from hunterx.domain.auth.models import (
    FINDINGS_KEY,
    AuthAccessState,
    AuthCookieObservation,
    AuthEndpointObservation,
    AuthEvidence,
    AuthSchemeObservation,
    AuthSurfaceKind,
    AuthSurfaceObservation,
    CSRFObservation,
    EvidenceStrength,
    EvidenceType,
    IdPObservation,
    MFAObservation,
    OAuthObservation,
    OIDCObservation,
    RoleObservation,
    TenantObservation,
    TokenStorageObservation,
    WebAuthnObservation,
    make_evidence,
    observations_from_payload,
    origin_of,
    record_from_dict,
    record_to_dict,
)
from hunterx.domain.auth.scope import AuthScopeEnforcer, AuthScopePolicy
from hunterx.domain.auth.strategy import AuthStrategyBuilder
from hunterx.domain.auth.validator import AuthValidator
from hunterx.domain.recon.models import ReconMode


class TestModels:
    def test_origin_of(self) -> None:
        assert origin_of("https://example.com/path?q=1") == "https://example.com"
        assert origin_of("not-a-url") == ""

    def test_serialization_roundtrip(self) -> None:
        surface = AuthSurfaceObservation(
            url="https://example.com/login",
            origin="https://example.com",
            surface_kind=AuthSurfaceKind.LOGIN,
            access_state=AuthAccessState.PUBLIC,
            indicators=("password input present",),
            confidence=0.7,
            evidence=(make_evidence(EvidenceType.HTML, "password input present"),),
        )
        payload = record_to_dict(surface)
        assert payload["type"] == "auth-surface"
        restored = record_from_dict(AuthSurfaceObservation, payload)
        assert restored == surface

    def test_observations_from_payload_dispatch(self) -> None:
        surface = AuthSurfaceObservation(url="u", origin="o", surface_kind=AuthSurfaceKind.LOGIN)
        cookie = AuthCookieObservation(name="session", origin="o")
        payload = {FINDINGS_KEY: [record_to_dict(surface), record_to_dict(cookie)]}
        records = observations_from_payload(payload)
        assert len(records) == 2
        assert isinstance(records[0], AuthSurfaceObservation)
        assert isinstance(records[1], AuthCookieObservation)

    def test_observations_from_payload_ignores_unknown_types(self) -> None:
        payload = {FINDINGS_KEY: [{"type": "not-a-record", "origin": "x"}]}
        assert observations_from_payload(payload) == []

    def test_evidence_roundtrip(self) -> None:
        evidence = make_evidence(EvidenceType.HTTP_HEADER, "www-authenticate: bearer")
        assert evidence.to_dict()["evidence_type"] == "http-header"
        restored = AuthEvidence.from_dict(evidence.to_dict())
        assert restored == evidence

    def test_record_discriminators(self) -> None:
        cases = [
            (AuthSurfaceObservation(url="u", origin="o"), "auth-surface"),
            (AuthEndpointObservation(url="u", origin="o"), "auth-endpoint"),
            (IdPObservation(name="Okta", origin="o"), "identity-provider"),
            (OAuthObservation(origin="o"), "oauth"),
            (OIDCObservation(origin="o"), "oidc"),
            (AuthSchemeObservation(origin="o"), "auth-scheme"),
            (AuthCookieObservation(name="session", origin="o"), "cookie"),
            (TokenStorageObservation(origin="o"), "token-storage"),
            (CSRFObservation(origin="o"), "csrf"),
            (MFAObservation(origin="o"), "mfa"),
            (WebAuthnObservation(origin="o"), "webauthn"),
            (RoleObservation(origin="o", name="admin"), "role"),
            (TenantObservation(origin="o", name="tenant-1"), "tenant"),
        ]
        for record, expected in cases:
            assert record_to_dict(record)["type"] == expected


class TestClassification:
    def test_classify_access_auth_required(self) -> None:
        classifier = AuthClassifier()
        assert classifier.classify_access(status_code=401) == AuthAccessState.AUTH_REQUIRED
        assert classifier.classify_access(www_authenticate=True) == AuthAccessState.AUTH_REQUIRED

    def test_classify_access_login_redirect(self) -> None:
        classifier = AuthClassifier()
        assert classifier.classify_access(login_redirect="/login") == AuthAccessState.AUTH_REQUIRED

    def test_classify_access_public_login_page(self) -> None:
        classifier = AuthClassifier()
        assert classifier.classify_access(url="/login", has_password_field=True) == AuthAccessState.PUBLIC

    def test_classify_surface_refines_unknown(self) -> None:
        classifier = AuthClassifier()
        surface = AuthSurfaceObservation(url="https://example.com/register", origin="https://example.com")
        classified = classifier.classify_surface(surface)
        assert classified.surface_kind == AuthSurfaceKind.REGISTRATION


class TestConfidence:
    def test_single_observation_confidence_bounded(self) -> None:
        engine = AuthConfidenceEngine()
        surface = AuthSurfaceObservation(url="u", origin="o", confidence=0.9)
        score = engine.observation_confidence(surface)
        assert 0.0 <= score <= 1.0

    def test_merged_confidence_raises_with_corroboration(self) -> None:
        engine = AuthConfidenceEngine()
        a = AuthSurfaceObservation(url="u", origin="o", confidence=0.7, source="web")
        b = AuthSurfaceObservation(url="u", origin="o", confidence=0.7, source="javascript")
        merged = engine.merged_confidence([a, b])
        assert merged > engine.observation_confidence(a)
        discounted = engine.merged_confidence([a, b], conflicted=True)
        assert discounted < merged

    def test_detection_score(self) -> None:
        engine = AuthConfidenceEngine()
        assert engine.detection_score([EvidenceStrength.STRONG]) > engine.detection_score([EvidenceStrength.WEAK])


class TestScope:
    def test_allows_name_within_root(self) -> None:
        enforcer = AuthScopeEnforcer(AuthScopePolicy(roots=frozenset({"example.com"})))
        assert enforcer.allows_name("app.example.com").allowed
        assert not enforcer.allows_name("evil.com").allowed

    def test_excluded_pattern(self) -> None:
        enforcer = AuthScopeEnforcer(
            AuthScopePolicy(roots=frozenset({"example.com"}), excluded_url_patterns=frozenset({"/admin"}))
        )
        assert not enforcer.allows_url("https://example.com/admin").allowed

    def test_observation_scope(self) -> None:
        enforcer = AuthScopeEnforcer(AuthScopePolicy(roots=frozenset({"example.com"})))
        observation = AuthSurfaceObservation(url="https://example.com/login", origin="https://example.com")
        assert enforcer.allows_observation(observation).allowed
        external = AuthSurfaceObservation(url="https://evil.com/x", origin="https://evil.com")
        assert not enforcer.allows_observation(external).allowed

    def test_scope_policy_to_scope(self) -> None:
        policy = AuthScopePolicy(roots=frozenset({"example.com"}), root_cidrs=frozenset({"10.0.0.0/8"}))
        scope = policy.to_scope()
        assert scope.roots == ("example.com",)
        assert "10.0.0.0/8" in scope.includes


class TestCorrelator:
    def test_correlates_and_merges(self) -> None:
        correlator = AuthCorrelator(scope=AuthScopePolicy(roots=frozenset({"example.com"})))
        a = AuthSurfaceObservation(url="https://example.com/login", origin="https://example.com", confidence=0.7)
        b = AuthSurfaceObservation(url="https://example.com/login", origin="https://example.com", confidence=0.7)
        result = correlator.correlate([a, b])
        assert len(result.records) == 1
        assert result.merged == 1

    def test_conflict_surface_kind_change(self) -> None:
        correlator = AuthCorrelator()
        a = AuthCookieObservation(name="session", origin="https://example.com", secure=True)
        b = AuthCookieObservation(name="session", origin="https://example.com", secure=False)
        result = correlator.correlate([a, b])
        assert result.conflicts, "conflicting cookie attributes must surface a conflict"

    def test_scoped_out_counted(self) -> None:
        correlator = AuthCorrelator(scope=AuthScopePolicy(roots=frozenset({"example.com"})))
        external = AuthSurfaceObservation(url="https://evil.com/x", origin="https://evil.com")
        result = correlator.correlate([external])
        assert result.scoped_out == 1
        assert result.records == ()


class TestHistory:
    def test_added_removed_changed(self) -> None:
        history = AuthHistory()
        old = [
            AuthCookieObservation(name="session", origin="https://example.com", secure=False),
        ]
        new = [
            AuthCookieObservation(name="session", origin="https://example.com", secure=True),
            AuthCookieObservation(name="csrf", origin="https://example.com"),
        ]
        comparison = history.compare(old, new)
        changes = {change.change_type for change in comparison.changes}
        assert "changed" in changes
        assert "added" in changes
        assert comparison.unchanged == 0

    def test_removed_detected(self) -> None:
        history = AuthHistory()
        old = [IdPObservation(name="Okta", origin="https://example.com")]
        comparison = history.compare(old, [])
        assert [c.change_type for c in comparison.changes] == ["removed"]

    def test_summarize(self) -> None:
        history = AuthHistory()
        old = [AuthCookieObservation(name="a", origin="o")]
        new = [AuthCookieObservation(name="b", origin="o")]
        summary = history.summarize(history.compare(old, new))
        assert summary["added"] == 1 and summary["removed"] == 1


class TestValidator:
    def test_valid_observation(self) -> None:
        validator = AuthValidator()
        observation = AuthSurfaceObservation(url="u", origin="https://example.com")
        result = validator.validate(observation)
        assert result.valid

    def test_missing_origin_invalid(self) -> None:
        validator = AuthValidator()
        observation = AuthCookieObservation(name="session", origin="")
        result = validator.validate(observation)
        assert not result.valid
        assert any(issue.code == "missing-origin" for issue in result.issues)

    def test_bad_confidence_invalid(self) -> None:
        validator = AuthValidator()
        observation = AuthSurfaceObservation(url="u", origin="o", confidence=2.0)
        result = validator.validate(observation)
        assert not result.valid


class TestStrategy:
    def test_build_defaults(self) -> None:
        strategy = AuthStrategyBuilder().build("https://example.com", mode=ReconMode.PASSIVE)
        assert strategy.tools == ("auth-analysis",)
        assert strategy.mode is ReconMode.PASSIVE
        assert strategy.include_endpoints is True

    def test_tools_available_in_passive(self) -> None:
        builder = AuthStrategyBuilder()
        assert builder.tools_for(ReconMode.PASSIVE) == ("auth-analysis",)

    def test_infer_target_kind(self) -> None:
        strategy = AuthStrategyBuilder().build("https://example.com/login")
        assert strategy.target_kind == "url"
