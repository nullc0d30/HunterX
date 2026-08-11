# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the technology fingerprinting domain.

Covers the canonical models, taxonomy, normalization, resolution, version
intelligence, signature-based detection, confidence scoring, correlation,
conflict handling, scope enforcement, history comparison and validation. All
tests are deterministic and require no I/O or external tools.
"""

from __future__ import annotations

from hunterx.domain.technology.confidence import TechnologyConfidenceEngine
from hunterx.domain.technology.conflicts import TechnologyConflictResolver
from hunterx.domain.technology.correlator import TechnologyCorrelator
from hunterx.domain.technology.detector import HttpEvidence, SignatureDetector
from hunterx.domain.technology.history import TechnologyHistory
from hunterx.domain.technology.models import (
    EvidenceStrength,
    EvidenceType,
    TechConflict,
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
from hunterx.domain.technology.normalizer import TechnologyNormalizer
from hunterx.domain.technology.resolver import TechnologyResolver
from hunterx.domain.technology.scope import TechnologyScopeEnforcer, TechnologyScopePolicy
from hunterx.domain.technology.strategy import TechStrategyBuilder
from hunterx.domain.technology.taxonomy import TECHNOLOGY_CATALOG
from hunterx.domain.technology.validator import TechnologyValidator
from hunterx.domain.technology.version import VersionResolver


class TestModels:
    def test_observation_normalizes_asset_and_name(self) -> None:
        observation = TechnologyObservation(asset="WWW.Example.COM.", raw_name="  Nginx/1.24.0  ")
        assert observation.asset == "www.example.com"
        assert observation.canonical_name == "Nginx/1.24.0"

    def test_observation_serialization_round_trip(self) -> None:
        observation = make_observation(
            "example.com",
            "nginx",
            canonical_name="Nginx",
            version="1.24.0",
            category=TechnologyCategory.WEB_SERVER,
            family=TechnologyFamily.WEB_SERVER,
            evidence=(
                TechnologyEvidence(
                    evidence_type=EvidenceType.RESPONSE_HEADER,
                    value="server: nginx/1.24.0",
                    strength=EvidenceStrength.STRONG,
                ),
            ),
        )
        payload = observation.to_dict()
        rebuilt = TechnologyObservation.from_dict(payload)
        assert rebuilt.key() == observation.key()
        assert rebuilt.canonical_name == "Nginx"
        assert rebuilt.version == "1.24.0"
        assert rebuilt.category is TechnologyCategory.WEB_SERVER
        assert rebuilt.family is TechnologyFamily.WEB_SERVER
        assert len(rebuilt.evidence) == 1
        assert rebuilt.evidence[0].evidence_type is EvidenceType.RESPONSE_HEADER

    def test_version_spec_range(self) -> None:
        spec = VersionSpec(lower="1.0", upper="2.0", confidence=VersionConfidence.RANGE)
        assert spec.value == "1.0..2.0"

    def test_observations_from_payload(self) -> None:
        observation = make_observation("example.com", "nginx")
        payload = {"technologies": [observation.to_dict()]}
        assert observations_from_payload(payload) == [observation]

    def test_infer_asset_type(self) -> None:
        assert infer_asset_type("https://example.com/x") == "url"
        assert infer_asset_type("192.0.2.10") == "ip"
        assert infer_asset_type("example.com") == "domain"
        assert infer_asset_type("www.example.com") == "hostname"


class TestTaxonomy:
    def test_catalog_has_golden_technologies(self) -> None:
        names = {definition.canonical_name for definition in TECHNOLOGY_CATALOG}
        for expected in ("Apache HTTP Server", "Nginx", "Microsoft IIS", "WordPress", "Drupal", "Joomla", "React", "Vue.js", "Angular", "Next.js", "PHP", "Node.js", "Django", "Flask", "Cloudflare", "Cloudflare WAF"):
            assert expected in names

    def test_every_definition_has_product_and_category(self) -> None:
        for definition in TECHNOLOGY_CATALOG:
            assert definition.product
            assert definition.category is not TechnologyCategory.OTHER or definition.canonical_name in ("Unknown",)


class TestNormalizer:
    def test_name_normalization(self) -> None:
        normalizer = TechnologyNormalizer()
        normalized = normalizer.normalize_name("  Apache   httpd  ")
        assert normalized.normalized == "apache httpd"
        assert normalized.token == "apachehttpd"

    def test_asset_normalization(self) -> None:
        normalizer = TechnologyNormalizer()
        assert normalizer.normalize_asset("https://WWW.Example.COM/") == "www.example.com"
        assert normalizer.normalize_asset("Example.COM.") == "example.com"


class TestResolver:
    def test_aliases_resolve_to_canonical(self) -> None:
        resolver = TechnologyResolver()
        assert resolver.resolve("apache").canonical_name == "Apache HTTP Server"
        assert resolver.resolve("Apache").canonical_name == "Apache HTTP Server"
        assert resolver.resolve("Apache httpd").canonical_name == "Apache HTTP Server"
        assert resolver.resolve("nginx").canonical_name == "Nginx"

    def test_inline_version_resolves_identity(self) -> None:
        resolver = TechnologyResolver()
        resolution = resolver.resolve("nginx/1.24.0")
        assert resolution.canonical_name == "Nginx"
        assert resolution.base_version == "1.24.0"

    def test_unknown_technology_is_preserved(self) -> None:
        resolver = TechnologyResolver()
        resolution = resolver.resolve("FancyWidget 9")
        assert not resolution.is_known
        assert resolution.canonical_name == "Fancywidget"

    def test_canonical_hint(self) -> None:
        resolver = TechnologyResolver()
        resolution = resolver.resolve("Nginx", canonical_hint="nginx")
        assert resolution.is_known
        assert resolution.canonical_name == "Nginx"


class TestVersion:
    def test_extract_embedded_version(self) -> None:
        resolver = VersionResolver()
        extraction = resolver.extract("nginx/1.24.0")
        assert extraction.version == "1.24.0"
        assert extraction.confidence is VersionConfidence.PROBABLE

    def test_extract_bare_version(self) -> None:
        resolver = VersionResolver()
        extraction = resolver.extract("1.24.0")
        assert extraction.version == "1.24.0"

    def test_unknown_version(self) -> None:
        resolver = VersionResolver()
        extraction = resolver.extract("nginx")
        assert extraction.version == ""
        assert extraction.confidence is VersionConfidence.UNKNOWN

    def test_classify_strong(self) -> None:
        resolver = VersionResolver()
        assert resolver.classify("1.24.0", strong=True) is VersionConfidence.CONFIRMED
        assert resolver.classify("1.24.0") is VersionConfidence.PROBABLE
        assert resolver.classify("") is VersionConfidence.UNKNOWN


class TestDetector:
    def test_detects_nginx_and_cloudflare(self) -> None:
        detector = SignatureDetector()
        evidence = HttpEvidence(
            url="https://example.com",
            status_code=200,
            headers={"Server": "nginx/1.24.0", "cf-ray": "abc123"},
        )
        observations = detector.detect(evidence, asset="example.com")
        names = {obs.canonical_name for obs in observations}
        assert "Nginx" in names
        assert "Cloudflare" in names
        nginx = next(obs for obs in observations if obs.canonical_name == "Nginx")
        assert nginx.version == "1.24.0"
        assert nginx.version_spec is not None
        assert nginx.version_spec.confidence is VersionConfidence.PROBABLE

    def test_meta_generator_detects_wordpress_with_version(self) -> None:
        detector = SignatureDetector()
        evidence = HttpEvidence(
            url="https://example.com",
            meta={"generator": "WordPress 6.0.2"},
            html="<p>wp-content</p>",
        )
        observations = detector.detect(evidence, asset="example.com")
        wordpress = next((obs for obs in observations if obs.canonical_name == "WordPress"), None)
        assert wordpress is not None
        assert wordpress.version == "6.0.2"

    def test_deterministic_output(self) -> None:
        detector = SignatureDetector()
        evidence = HttpEvidence(url="https://example.com", headers={"Server": "nginx"})
        first = detector.detect(evidence, asset="example.com")
        second = detector.detect(evidence, asset="example.com")

        def identity(obs: TechnologyObservation) -> tuple[str, str, float]:
            return (obs.canonical_name, obs.version, round(obs.confidence, 4))

        assert [identity(obs) for obs in first] == [identity(obs) for obs in second]

    def test_weak_signature_is_not_promoted_to_version(self) -> None:
        detector = SignatureDetector()
        evidence = HttpEvidence(url="https://example.com", html="<p>tailwind text-sm</p>")
        observations = detector.detect(evidence, asset="example.com")
        tailwind = next((obs for obs in observations if obs.canonical_name == "Tailwind CSS"), None)
        assert tailwind is not None
        assert not tailwind.version


class TestConfidence:
    def test_observation_confidence_scoring(self) -> None:
        engine = TechnologyConfidenceEngine()
        observation = make_observation(
            "example.com",
            "nginx",
            tool_id="httpx",
            evidence=(
                TechnologyEvidence(
                    evidence_type=EvidenceType.RESPONSE_HEADER,
                    value="server: nginx",
                    strength=EvidenceStrength.STRONG,
                ),
            ),
        )
        score = engine.observation_confidence(observation)
        assert 0.0 <= score <= 1.0

    def test_corroboration_raises_confidence(self) -> None:
        engine = TechnologyConfidenceEngine()
        a = make_observation("example.com", "nginx", tool_id="httpx")
        b = make_observation("example.com", "nginx", tool_id="whatweb")
        merged = engine.merged_confidence([a, b])
        assert merged > engine.observation_confidence(a)

    def test_conflict_discounts_confidence(self) -> None:
        engine = TechnologyConfidenceEngine()
        a = make_observation("example.com", "nginx", tool_id="httpx", version="1.24.0")
        b = make_observation("example.com", "nginx", tool_id="whatweb", version="1.18.0")
        conflicted = engine.merged_confidence([a, b], conflicted=True)
        plain = engine.merged_confidence([a, b], conflicted=False)
        assert conflicted < plain

    def test_unknown_tool_scores_low(self) -> None:
        engine = TechnologyConfidenceEngine()
        observation = make_observation("example.com", "nginx", tool_id="unknown-tool")
        assert engine.observation_confidence(observation) < 0.3


class TestCorrelator:
    def _obs(self, name: str, tool: str, *, version: str = "", asset: str = "example.com") -> TechnologyObservation:
        return make_observation(
            asset,
            name,
            canonical_name=name,
            version=version,
            tool_id=tool,
            source=tool,
        )

    def test_merges_corroborating_observations(self) -> None:
        correlator = TechnologyCorrelator()
        result = correlator.correlate([self._obs("Nginx", "httpx"), self._obs("Nginx", "whatweb")])
        assert len(result.technologies) == 1
        assert result.technologies[0].canonical_name == "Nginx"
        assert "httpx" in result.technologies[0].source

    def test_preserves_version_conflict(self) -> None:
        correlator = TechnologyCorrelator()
        a = self._obs("Nginx", "httpx", version="1.24.0")
        b = self._obs("Nginx", "whatweb", version="1.18.0")
        result = correlator.correlate([a, b])
        assert len(result.conflicts) == 1
        conflict = result.conflicts[0]
        assert conflict.conflict_type == "version"
        assert conflict.selected in ("1.24.0", "1.18.0")

    def test_scoped_out_observations_are_counted(self) -> None:
        scope = TechnologyScopePolicy(roots=frozenset({"example.com"}))
        correlator = TechnologyCorrelator(scope=scope)
        out_of_scope = self._obs("Nginx", "httpx", asset="evil.com")
        result = correlator.correlate([out_of_scope])
        assert result.scoped_out == 1
        assert result.technologies == ()

    def test_below_threshold_observations_dropped(self) -> None:
        correlator = TechnologyCorrelator(min_confidence=0.9)
        weak = self._obs("Nginx", "unknown-tool")
        result = correlator.correlate([weak])
        assert result.dropped == 1
        assert result.technologies == ()


class TestConflictResolver:
    def test_most_confident_strategy(self) -> None:
        resolver = TechnologyConflictResolver(strategy="most-confident")
        a = make_observation("example.com", "Nginx", tool_id="httpx", version="1.24.0")
        b = make_observation("example.com", "Nginx", tool_id="whatweb", version="1.18.0")
        resolution = resolver.resolve([a, b])
        assert resolution is not None
        assert resolution.selected_value == "1.24.0"

    def test_invalid_strategy_rejected(self) -> None:
        try:
            TechnologyConflictResolver(strategy="bogus")
        except ValueError:
            return
        raise AssertionError("invalid strategy must raise")


class TestScope:
    def test_allow_and_deny(self) -> None:
        policy = TechnologyScopePolicy(
            roots=frozenset({"example.com"}),
            excludes=frozenset({"admin.example.com"}),
        )
        enforcer = TechnologyScopeEnforcer(policy)
        assert enforcer.allows_name("www.example.com").allowed
        assert not enforcer.allows_name("admin.example.com").allowed
        assert not enforcer.allows_name("evil.com").allowed

    def test_empty_policy_is_fail_open(self) -> None:
        enforcer = TechnologyScopeEnforcer()
        assert enforcer.allows_name("anything.example").allowed
        assert enforcer.allows_target(TechTarget("anything.example")).allowed

    def test_cidr_scope(self) -> None:
        policy = TechnologyScopePolicy(root_cidrs=frozenset({"192.0.2.0/24"}))
        enforcer = TechnologyScopeEnforcer(policy)
        assert enforcer.allows_address("192.0.2.10").allowed
        assert not enforcer.allows_address("198.51.100.10").allowed

    def test_filter_observations(self) -> None:
        policy = TechnologyScopePolicy(roots=frozenset({"example.com"}))
        enforcer = TechnologyScopeEnforcer(policy)
        in_scope = make_observation("www.example.com", "Nginx")
        out_scope = make_observation("evil.com", "Nginx")
        assert enforcer.filter_observations([in_scope, out_scope]) == [in_scope]


class TestHistory:
    def _obs(self, name: str, *, version: str = "", asset: str = "example.com") -> TechnologyObservation:
        return make_observation(asset, name, canonical_name=name, version=version)

    def test_detects_added_removed_changed(self) -> None:
        history = TechnologyHistory()
        previous = [self._obs("Nginx", version="1.18.0"), self._obs("OldFramework")]
        current = [self._obs("Nginx", version="1.24.0"), self._obs("NewFramework")]
        comparison = history.compare(previous, current)
        types = {change.change_type for change in comparison.changes}
        assert "changed" in types
        assert "added" in types
        assert "removed" in types

    def test_summary(self) -> None:
        history = TechnologyHistory()
        comparison = history.compare([self._obs("Nginx")], [self._obs("Nginx"), self._obs("PHP")])
        summary = history.summarize(comparison)
        assert summary["added"] == 1


class TestValidator:
    def test_invalid_observations_rejected(self) -> None:
        validator = TechnologyValidator()
        result = validator.validate(TechnologyObservation(asset="", raw_name=""))
        assert not result.valid
        assert result.status == "invalid"

    def test_valid_observation_accepted(self) -> None:
        validator = TechnologyValidator()
        observation = make_observation("example.com", "Nginx")
        result = validator.validate(observation)
        assert result.valid
        assert result.status == "valid"


class TestStrategy:
    def test_active_tools(self) -> None:
        builder = TechStrategyBuilder()
        strategy = builder.build("example.com", mode="active")
        assert "httpx" in strategy.tools
        assert "whatweb" in strategy.tools

    def test_passive_selects_no_tools(self) -> None:
        builder = TechStrategyBuilder()
        strategy = builder.build("example.com", mode="passive")
        assert strategy.tools == ()

    def test_target_kind_inference(self) -> None:
        builder = TechStrategyBuilder()
        assert builder.build("https://example.com").target_kind == "url"
        assert builder.build("192.0.2.10").target_kind == "ip"
        assert builder.build("example.com").target_kind == "domain"


class TestBatch:
    def test_batch_counts(self) -> None:
        batch = TechnologyBatch(mission_id="m1", correlation_id="c1", target=TechTarget("example.com"))
        batch.add_technology(make_observation("example.com", "Nginx", version="1.24.0"))
        batch.add_technology(make_observation("example.com", "PHP", version="8.1"))
        batch.add_technology(make_observation("example.com", "React"))
        batch.add_conflict(TechConflict(asset="example.com", technology="Nginx"))
        assert batch.technology_count() == 3
        assert batch.distinct_technologies() == 3
        assert batch.version_count() == 2
        assert batch.conflict_count() == 1
