# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the cloud & SaaS intelligence domain layer.

Exercises the canonical models (serialization round-trips, type discriminators,
evidence), the evidence-based provider detection registry, classification,
deterministic confidence scoring, scope enforcement, correlation with conflict
preservation, historical diffing, validation and the collection strategy.
"""

from __future__ import annotations

from hunterx.domain.cloud.classification import CloudClassifier
from hunterx.domain.cloud.confidence import CloudConfidenceEngine
from hunterx.domain.cloud.conflicts import CloudConflictResolver
from hunterx.domain.cloud.correlator import CloudCorrelator
from hunterx.domain.cloud.history import CloudHistory
from hunterx.domain.cloud.models import (
    CloudEvidence,
    CloudInput,
    CloudProviderObservation,
    CloudResourceObservation,
    CloudServiceObservation,
    EvidenceStrength,
    EvidenceType,
    SaaSProviderObservation,
    StorageResourceObservation,
    WebhookObservation,
    make_evidence,
    observations_from_payload,
    record_from_dict,
    record_to_dict,
)
from hunterx.domain.cloud.providers import ProviderCatalog
from hunterx.domain.cloud.redaction import fingerprint, sanitize_evidence
from hunterx.domain.cloud.scope import CloudScopeEnforcer, CloudScopePolicy
from hunterx.domain.cloud.strategy import CloudStrategyBuilder
from hunterx.domain.cloud.validator import CloudValidator
from hunterx.domain.recon.models import ReconMode


class TestModels:
    def test_provider_serialization_roundtrip(self) -> None:
        provider = CloudProviderObservation(
            name="aws",
            display_name="AWS",
            evidence_indicators=("dns-cname",),
            confidence=0.9,
            evidence=(make_evidence(EvidenceType.DNS_CNAME, "*.cloudfront.net", strength=EvidenceStrength.STRONG),),
        )
        payload = record_to_dict(provider)
        assert payload["type"] == "cloud-provider"
        restored = record_from_dict(CloudProviderObservation, payload)
        assert restored == provider

    def test_resource_serialization_roundtrip(self) -> None:
        resource = CloudResourceObservation(
            provider="aws",
            resource_kind="bucket",
            identifier="acme-assets",
            service="s3",
            region="us-east-1",
            endpoint="acme-assets.s3.us-east-1.amazonaws.com",
            public="public",
        )
        payload = record_to_dict(resource)
        assert payload["type"] == "cloud-resource"
        restored = record_from_dict(CloudResourceObservation, payload)
        assert restored == resource

    def test_payload_dispatch_rebuilds_typed_records(self) -> None:
        records = [
            CloudProviderObservation(name="aws"),
            SaaSProviderObservation(name="stripe"),
            StorageResourceObservation(provider="aws", identifier="bkt"),
            WebhookObservation(endpoint="https://example.com/hooks/x", direction="inbound"),
        ]
        payload = {"cloud": [record_to_dict(record) for record in records]}
        restored = observations_from_payload(payload)
        assert [type(item) for item in restored] == [type(item) for item in records]

    def test_payload_dispatch_ignores_unknown_types(self) -> None:
        payload = {"cloud": [{"type": "not-a-cloud-record", "name": "x"}]}
        assert observations_from_payload(payload) == []

    def test_evidence_roundtrip(self) -> None:
        evidence = make_evidence(EvidenceType.HTTP_HEADER, "Server: AmazonS3", strength=EvidenceStrength.STRONG)
        restored = CloudEvidence.from_dict(evidence.to_dict())
        assert restored == evidence

    def test_observation_keys_are_stable(self) -> None:
        a = CloudServiceObservation(provider="aws", service="s3", endpoint="acme-assets.s3.amazonaws.com")
        b = CloudServiceObservation(provider="aws", service="s3", endpoint="acme-assets.s3.amazonaws.com")
        assert a.key() == b.key() == "service:aws|s3|acme-assets.s3.amazonaws.com"


class TestProviderDetection:
    def test_aws_cloudfront_hostname(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_hostname("d3k2j9h4x1c7y8.cloudfront.net")
        assert any(match.provider == "aws" and match.service == "cloudfront" for match in matches)
        assert matches[0].strength == EvidenceStrength.STRONG

    def test_aws_s3_bucket_hostname(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_hostname("acme-assets.s3.us-east-1.amazonaws.com")
        assert any(match.provider == "aws" and match.service == "s3" for match in matches)
        region = next((match.region for match in matches if match.region), "")
        assert region == "us-east-1"

    def test_azure_app_service_hostname(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_hostname("contoso-app.azurewebsites.net")
        assert any(match.provider == "azure" and match.service == "app-service" for match in matches)

    def test_gcp_cloud_run_hostname(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_hostname("globe-api-abcdef123456.us-central1.run.app")
        assert any(match.provider == "gcp" and match.service == "cloud-run" for match in matches)
        region = next((match.region for match in matches if match.region), "")
        assert region == "us-central1"

    def test_cloudflare_header(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_header("cf-ray", "6f2a9c4e1b8d4f6a-DFW")
        assert any(match.provider == "cloudflare" for match in matches)

    def test_aws_header_banner(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_header("Server", "AmazonS3")
        assert any(match.provider == "aws" and match.service == "s3" for match in matches)

    def test_tls_org_detection(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_tls({"subject_org": "Cloudflare, Inc.", "issuer_org": "Cloudflare, Inc."})
        assert any(match.provider == "cloudflare" for match in matches)

    def test_technology_detection(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_technology({"name": "Kubernetes"})
        assert any(match.provider == "kubernetes" for match in matches)

    def test_js_sdk_detection(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_javascript("import { S3Client } from '@aws-sdk/client-s3'")
        assert any(match.provider == "aws" for match in matches)

    def test_saas_hostname_detection(self) -> None:
        catalog = ProviderCatalog()
        matches = catalog.match_saas_hostname("hooks.slack.com")
        assert any(match.provider == "slack" for match in matches)

    def test_no_match_on_plain_hostname(self) -> None:
        catalog = ProviderCatalog()
        assert catalog.match_hostname("plain.example.com") == []

    def test_region_extraction_from_documentation(self) -> None:
        from hunterx.domain.cloud.providers import extract_region

        assert extract_region("aws", "deploy to us-west-2 cluster") == "us-west-2"
        assert extract_region("aws", "deploy to eu-west-1") == "eu-west-1"
        assert extract_region("gcp", "us-central1") == "us-central1"

    def test_account_identifier_extraction(self) -> None:
        from hunterx.domain.cloud.providers import extract_aws_account

        assert extract_aws_account("arn:aws:iam::123456789012:role/cicd") == "123456789012"
        assert extract_aws_account("no account here") == ""


class TestClassification:
    def test_service_category_mapping(self) -> None:
        classifier = CloudClassifier()
        assert classifier.service_category("s3") == "storage"
        assert classifier.service_category("lambda") == "serverless"
        assert classifier.service_category("eks") == "kubernetes"
        assert classifier.service_category("unknown-thing") == "unknown"

    def test_plane_classification(self) -> None:
        classifier = CloudClassifier()
        assert classifier.classify_plane("console.aws.amazon.com") == "management"
        assert classifier.classify_plane("s3.amazonaws.com", service="s3") == "data"
        assert classifier.classify_plane("example.com") == "unknown"

    def test_exposure_classification(self) -> None:
        classifier = CloudClassifier()
        assert classifier.classify_exposure("s3.amazonaws.com", "aws", public_hint=True) == "public"
        assert classifier.classify_exposure("10.0.0.5", "aws") == "private-indicator"
        assert classifier.classify_exposure("cdn.example.com", "aws") == "public-indicator"

    def test_environment_classification(self) -> None:
        classifier = CloudClassifier()
        assert classifier.classify_environment("staging.example.com") == "staging"
        assert classifier.classify_environment("prod.example.com") == "production"
        assert classifier.classify_environment("dev.example.com") == "development"
        assert classifier.classify_environment("plain.example.com") == "unknown"

    def test_exposure_indicator_kinds_are_intelligence(self) -> None:
        classifier = CloudClassifier()
        assert classifier.classify_exposure_indicator(resource_kind="storage", public="public") == "public-storage"
        assert classifier.classify_exposure_indicator(dangling=True) == "dangling-resource"
        assert classifier.classify_exposure_indicator() == "unknown"


class TestConfidence:
    def test_scores_are_bounded(self) -> None:
        engine = CloudConfidenceEngine()
        provider = CloudProviderObservation(
            name="aws", confidence=0.9, evidence=(make_evidence(EvidenceType.DNS_CNAME, "x"),)
        )
        score = engine.observation_confidence(provider)
        assert 0.0 <= score <= 1.0

    def test_merged_confidence_boosted_by_corroboration(self) -> None:
        engine = CloudConfidenceEngine()
        a = CloudProviderObservation(name="aws", confidence=0.7, source="dns")
        b = CloudProviderObservation(name="aws", confidence=0.7, source="http")
        merged = engine.merged_confidence([a, b])
        single = engine.observation_confidence(a)
        assert merged > single

    def test_conflict_discount_lowers_score(self) -> None:
        engine = CloudConfidenceEngine()
        a = CloudProviderObservation(name="aws", confidence=0.9, source="dns")
        b = CloudProviderObservation(name="azure", confidence=0.9, source="http")
        conflicted = engine.merged_confidence([a, b], conflicted=True)
        clean = engine.merged_confidence([a, b])
        assert conflicted < clean

    def test_confidence_is_deterministic(self) -> None:
        engine = CloudConfidenceEngine()
        observation = CloudProviderObservation(name="aws", confidence=0.8)
        assert engine.observation_confidence(observation) == engine.observation_confidence(observation)


class TestScope:
    def test_root_scope_allows_subdomain(self) -> None:
        enforcer = CloudScopeEnforcer(CloudScopePolicy(roots=frozenset({"example.com"})))
        assert enforcer.allows_name("www.example.com").allowed
        assert not enforcer.allows_name("evil.org").allowed

    def test_excluded_name_denied(self) -> None:
        enforcer = CloudScopeEnforcer(
            CloudScopePolicy(roots=frozenset({"example.com"}), excludes=frozenset({"admin.example.com"}))
        )
        assert not enforcer.allows_name("admin.example.com").allowed

    def test_url_pattern_exclusion(self) -> None:
        enforcer = CloudScopeEnforcer(
            CloudScopePolicy(roots=frozenset({"example.com"}), excluded_url_patterns=frozenset({"/logout"}))
        )
        assert not enforcer.allows_url("https://example.com/logout").allowed
        assert enforcer.allows_url("https://example.com/home").allowed

    def test_target_admission(self) -> None:
        from hunterx.domain.cloud.models import CloudTarget

        enforcer = CloudScopeEnforcer(CloudScopePolicy(roots=frozenset({"example.com"})))
        assert enforcer.allows_target(CloudTarget("example.com", target_type="domain")).allowed
        assert not enforcer.allows_target(CloudTarget("evil.org", target_type="domain")).allowed


class TestCorrelator:
    def test_duplicates_merged(self) -> None:
        correlator = CloudCorrelator()
        a = CloudProviderObservation(name="aws", source="dns")
        b = CloudProviderObservation(name="aws", source="http")
        result = correlator.correlate([a, b])
        assert len(result.records) == 1
        assert result.merged == 1

    def test_conflicting_providers_preserved(self) -> None:
        correlator = CloudCorrelator()
        a = CloudProviderObservation(name="aws", source="dns")
        b = CloudProviderObservation(name="aws", source="dns", confidence=0.2)
        result = correlator.correlate([a, b])
        assert len(result.records) == 1
        assert result.records[0].name == "aws"

    def test_out_of_scope_observations_dropped(self) -> None:
        policy = CloudScopePolicy(roots=frozenset({"example.com"}))
        correlator = CloudCorrelator(scope=policy)
        provider = CloudProviderObservation(name="aws", target_key="evil.org", source="dns")
        result = correlator.correlate([provider])
        assert result.scoped_out == 1
        assert result.records == ()

    def test_low_confidence_observations_dropped(self) -> None:
        correlator = CloudCorrelator(min_confidence=0.9)
        provider = CloudProviderObservation(name="aws", confidence=0.4, source="cloud")
        result = correlator.correlate([provider])
        assert result.dropped == 1
        assert result.records == ()

    def test_conflict_resolver_deterministic(self) -> None:
        resolver = CloudConflictResolver()
        a = CloudProviderObservation(name="aws", confidence=0.8, source="dns")
        b = CloudProviderObservation(name="azure", confidence=0.9, source="http")
        result = resolver.resolve([a, b], subject="provider", subject_type="provider")
        assert result.selected.name == "azure"
        assert result.conflict is not None


class TestHistory:
    def test_detects_added_removed_changed(self) -> None:
        history = CloudHistory()
        old = [CloudServiceObservation(provider="aws", service="s3", endpoint="a.s3.amazonaws.com", source="dns")]
        new = [
            CloudServiceObservation(provider="aws", service="s3", endpoint="b.s3.amazonaws.com", source="dns"),
            CloudServiceObservation(
                provider="azure", service="app-service", endpoint="x.azurewebsites.net", source="dns"
            ),
        ]
        comparison = history.compare(old, new)
        changes = {change.change_type for change in comparison.changes}
        assert {"added", "removed"} <= changes

    def test_identical_snapshots_no_changes(self) -> None:
        history = CloudHistory()
        snapshot = [CloudServiceObservation(provider="aws", service="s3", endpoint="a.s3.amazonaws.com", source="dns")]
        comparison = history.compare(snapshot, snapshot)
        assert comparison.changes == ()
        assert comparison.unchanged == 1

    def test_summarize_counts(self) -> None:
        history = CloudHistory()
        comparison = history.compare([], [CloudProviderObservation(name="aws", source="dns")])
        summary = history.summarize(comparison)
        assert summary["added"] == 1


class TestValidator:
    def test_missing_identifier_flagged(self) -> None:
        validator = CloudValidator()
        result = validator.validate(CloudResourceObservation(provider="aws", identifier=""))
        assert not result.valid
        assert any(issue.code == "missing-identifier" for issue in result.issues)

    def test_bad_confidence_flagged(self) -> None:
        validator = CloudValidator()
        result = validator.validate(CloudProviderObservation(name="aws", confidence=1.5))
        assert not result.valid
        assert any(issue.code == "bad-confidence" for issue in result.issues)

    def test_valid_observation_passes(self) -> None:
        validator = CloudValidator()
        result = validator.validate(CloudProviderObservation(name="aws", confidence=0.8))
        assert result.valid

    def test_filter_valid_preserves_order(self) -> None:
        validator = CloudValidator()
        observations = [
            CloudProviderObservation(name="aws", confidence=0.8),
            CloudResourceObservation(provider="aws", identifier=""),
            CloudProviderObservation(name="azure", confidence=0.7),
        ]
        filtered = validator.filter_valid(observations)
        assert [item.name for item in filtered] == ["aws", "azure"]


class TestStrategy:
    def test_build_defaults(self) -> None:
        builder = CloudStrategyBuilder()
        strategy = builder.build("example.com", mode=ReconMode.PASSIVE)
        assert strategy.target == "example.com"
        assert strategy.tools == ("cloud-analysis",)
        assert strategy.mode == ReconMode.PASSIVE

    def test_infers_target_kind(self) -> None:
        builder = CloudStrategyBuilder()
        assert builder.build("https://example.com").target_kind == "url"
        assert builder.build("192.0.2.1").target_kind == "ip"

    def test_tools_for_mode(self) -> None:
        builder = CloudStrategyBuilder()
        assert builder.tools_for(ReconMode.PASSIVE) == ("cloud-analysis",)


class TestRedaction:
    def test_secret_pattern_masked(self) -> None:
        assert "AKIA" not in sanitize_evidence("AKIAIOSFODNN7EXAMPLE")
        assert "sk_live" not in sanitize_evidence("sk_live_51ABCdefGHIjklMNO")

    def test_plain_evidence_truncated(self) -> None:
        value = sanitize_evidence("x" * 500)
        assert len(value) <= 256

    def test_fingerprint_is_stable_and_small(self) -> None:
        assert fingerprint("WEBHOOK_SECRET") == fingerprint("WEBHOOK_SECRET")
        assert fingerprint("WEBHOOK_SECRET") != fingerprint("API_KEY")
        assert len(fingerprint("anything")) == 24


class TestCloudInput:
    def test_bundle_roundtrip(self) -> None:
        bundle = CloudInput(
            target="example.com",
            domain="example.com",
            records=({"name": "a.example.com", "type": "CNAME", "cname_target": "b.cloudfront.net"},),
            headers=(("Server", "AmazonS3"),),
        )
        assert bundle.target == "example.com"
        assert bundle.records[0]["cname_target"] == "b.cloudfront.net"
