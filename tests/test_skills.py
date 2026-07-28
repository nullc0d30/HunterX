from __future__ import annotations

import pytest
from typing import List

from core.skills.base import SecuritySkill
from core.skills.registry import SkillRegistry
from core.skills.loader import SkillLoader
from core.skills.metadata import SkillMetadata, RiskLevel, NoiseLevel
from core.skills.capability import SkillCapability, SkillCapabilityRegistry
from core.skills.executor import SkillExecutor
from core.skills.planner import SkillPlanner
from core.skills.validator import SkillValidator
from core.skills.context import SkillContext
from core.skills.result import SkillResult, SkillStatus
from core.skills.policy import SkillPolicy, SkillSafetyLevel
from core.skills.cache import SkillCache
from core.skills.telemetry import SkillTelemetry
from core.skills.marketplace import SkillMarketplace
from core.reasoning.goals import Goal, GoalType


# --- Fixtures ---

@pytest.fixture
def sample_skill():
    class TestSkill(SecuritySkill):
        def _create_metadata(self) -> SkillMetadata:
            return SkillMetadata.create(
                skill_id="test_skill",
                name="Test Skill",
                description="A test skill",
                version="1.0.0",
                author="Test",
                tags=["test"],
                risk_level=RiskLevel.LOW,
                noise_level=NoiseLevel.LOW,
            )

        def _capabilities(self) -> List[SkillCapability]:
            return [SkillCapability.GENERIC]

        def _on_execute(self, target: str, context=None) -> SkillResult:
            return SkillResult.success(
                skill_id="test_skill",
                confidence=0.9,
                findings=[{"type": "test_finding", "detail": f"Analyzed {target}"}],
            )

    skill = TestSkill()
    skill._capabilities = [SkillCapability.GENERIC]
    return skill


@pytest.fixture
def registry():
    r = SkillRegistry()
    r.clear()
    return r


@pytest.fixture
def cache():
    return SkillCache()


# --- SkillMetadata Tests ---

class TestSkillMetadata:
    def test_create_default(self):
        m = SkillMetadata.create(
            skill_id="test_id",
            name="Test Skill",
            description="A test skill",
        )
        assert m.skill_id == "test_id"
        assert m.name == "Test Skill"
        assert m.version == "1.0.0"
        assert m.risk_level == RiskLevel.LOW
        assert m.noise_level == NoiseLevel.LOW

    def test_create_with_all_fields(self):
        m = SkillMetadata.create(
            skill_id="advanced",
            name="Advanced",
            description="Advanced skill",
            version="2.0.0",
            author="HunterX Core",
            license="Apache-2.0",
            tags=["advanced", "scan"],
            categories=["recon"],
            risk_level=RiskLevel.MEDIUM,
            noise_level=NoiseLevel.MEDIUM,
            mitre_techniques=["T1595"],
            cwe_ids=["CWE-200"],
        )
        assert m.version == "2.0.0"
        assert m.risk_level == RiskLevel.MEDIUM
        assert "T1595" in m.mitre_techniques

    def test_to_dict(self):
        m = SkillMetadata.create(skill_id="s1", name="S1", description="desc")
        d = m.to_dict()
        assert d["skill_id"] == "s1"
        assert d["name"] == "S1"
        assert d["risk_level"] == "low"


# --- SkillCapability Tests ---

class TestSkillCapability:
    def test_registry_register_and_get(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("s1", [SkillCapability.LFI, SkillCapability.SQL_INJECTION])
        caps = SkillCapabilityRegistry.get("s1")
        assert SkillCapability.LFI in caps
        assert SkillCapability.SQL_INJECTION in caps

    def test_find_by_capability(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("s1", [SkillCapability.SSRF])
        SkillCapabilityRegistry.register("s2", [SkillCapability.SSTI])
        found = SkillCapabilityRegistry.find_by_capability(SkillCapability.SSRF)
        assert "s1" in found
        assert "s2" not in found

    def test_unregister(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("s1", [SkillCapability.XXE])
        SkillCapabilityRegistry.unregister("s1")
        assert SkillCapabilityRegistry.get("s1") == set()

    def test_all_capabilities_defined(self):
        assert len(SkillCapability) >= 40


# --- SkillResult Tests ---

class TestSkillResult:
    def test_success_factory(self):
        r = SkillResult.success("s1", confidence=0.8, findings=[{"type": "test"}])
        assert r.skill_id == "s1"
        assert r.status == SkillStatus.COMPLETED
        assert r.confidence == 0.8

    def test_failure_factory(self):
        r = SkillResult.failure("s1", error_message="something broke")
        assert r.status == SkillStatus.FAILED
        assert r.error_message == "something broke"

    def test_to_dict(self):
        r = SkillResult.success("s1")
        d = r.to_dict()
        assert d["skill_id"] == "s1"
        assert d["status"] == "completed"

    def test_to_json(self):
        r = SkillResult.success("s1")
        j = r.to_json()
        assert '"skill_id": "s1"' in j


# --- SkillPolicy Tests ---

class TestSkillPolicy:
    def test_default_policy(self):
        p = SkillPolicy()
        assert p.safety_level == SkillSafetyLevel.BALANCED
        assert p.allow_destructive is False

    def test_safe_preset(self):
        from core.skills.policy import SAFETY_PRESETS
        preset = SAFETY_PRESETS[SkillSafetyLevel.SAFE]
        assert preset["allow_destructive"] is False
        assert preset["min_confidence"] == 0.9

    def test_research_preset(self):
        from core.skills.policy import SAFETY_PRESETS
        preset = SAFETY_PRESETS[SkillSafetyLevel.RESEARCH]
        assert preset["allow_destructive"] is True
        assert preset["min_confidence"] == 0.3

    def test_to_dict(self):
        p = SkillPolicy()
        d = p.to_dict()
        assert d["safety_level"] == "balanced"


# --- SkillValidator Tests ---

class TestSkillValidator:
    def test_validate_target_valid(self):
        assert SkillValidator.validate_target("http://example.com") is None

    def test_validate_target_empty(self):
        assert SkillValidator.validate_target("") is not None

    def test_validate_target_too_long(self):
        assert SkillValidator.validate_target("a" * 9999) is not None

    def test_validate_policy_warnings(self):
        m = SkillMetadata.create(skill_id="s1", name="S1", description="D", risk_level=RiskLevel.CRITICAL)
        p = SkillPolicy(safety_level=SkillSafetyLevel.SAFE, allow_destructive=False)
        warnings = SkillValidator.validate_policy(m, p)
        assert len(warnings) > 0

    def test_validate_policy_no_warnings(self):
        m = SkillMetadata.create(skill_id="s1", name="S1", description="D", risk_level=RiskLevel.LOW)
        p = SkillPolicy()
        warnings = SkillValidator.validate_policy(m, p)
        assert len(warnings) == 0

    def test_validate_result_success(self):
        r = SkillResult.success("s1", confidence=0.8)
        assert SkillValidator.validate_result(r, min_confidence=0.5) is True

    def test_validate_result_failure(self):
        r = SkillResult.failure("s1")
        assert SkillValidator.validate_result(r) is False

    def test_validate_evidence(self):
        r = SkillResult.success("s1", confidence=0.9, evidence=[{"source": "test"}])
        assert SkillValidator.validate_evidence(r) == []

    def test_validate_evidence_missing_source(self):
        r = SkillResult.success("s1", confidence=0.9, evidence=[{"data": "no source"}])
        issues = SkillValidator.validate_evidence(r)
        assert len(issues) > 0

    def test_validate_schema_valid(self):
        data = {"name": "test", "value": 42}
        schema = {"required": ["name"], "properties": {"name": {"type": "string"}}}
        assert SkillValidator.validate_schema(data, schema) == []

    def test_validate_schema_missing(self):
        data = {"value": 42}
        schema = {"required": ["name"], "properties": {"name": {"type": "string"}}}
        errors = SkillValidator.validate_schema(data, schema)
        assert len(errors) > 0


# --- SkillCache Tests ---

class TestSkillCache:
    def test_set_and_get(self, cache):
        r = SkillResult.success("s1")
        cache.set("s1", "http://example.com", r)
        cached = cache.get("s1", "http://example.com")
        assert cached is not None
        assert cached.skill_id == "s1"

    def test_cache_miss(self, cache):
        assert cache.get("nonexistent", "target") is None

    def test_cache_invalidate(self, cache):
        r = SkillResult.success("s1")
        cache.set("s1", "http://example.com", r)
        cache.invalidate("s1", "http://example.com")
        assert cache.get("s1", "http://example.com") is None

    def test_cache_stats(self, cache):
        r = SkillResult.success("s1")
        cache.set("s1", "t1", r)
        cache.get("s1", "t1")
        cache.get("s1", "missing")
        stats = cache.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1

    def test_cache_clear(self, cache):
        r = SkillResult.success("s1")
        cache.set("s1", "t1", r)
        cache.clear()
        assert cache.get_stats()["entries"] == 0


# --- SkillTelemetry Tests ---

class TestSkillTelemetry:
    def test_record_and_stats(self):
        t = SkillTelemetry()
        t.record("s1", 100.0, True, confidence=0.9, risk_score=0.1)
        t.record("s1", 200.0, False, confidence=0.5, risk_score=0.5)
        stats = t.get_stats("s1")
        assert stats["total_executions"] == 2
        assert stats["success_count"] == 1
        assert stats["avg_execution_time_ms"] == 150.0

    def test_empty_stats(self):
        t = SkillTelemetry()
        stats = t.get_stats("nonexistent")
        assert stats["total_executions"] == 0

    def test_get_summary(self):
        t = SkillTelemetry()
        t.record("s1", 100.0, True)
        t.record("s2", 200.0, False)
        summary = t.get_summary()
        assert "s1" in summary
        assert "s2" in summary

    def test_clear(self):
        t = SkillTelemetry()
        t.record("s1", 100.0, True)
        t.clear("s1")
        assert t.get_stats("s1")["total_executions"] == 0


# --- SkillRegistry Tests ---

class TestSkillRegistry:
    def test_singleton(self):
        r1 = SkillRegistry()
        r2 = SkillRegistry()
        assert r1 is r2

    def test_register_and_get(self, sample_skill, registry):
        registry.register(sample_skill)
        retrieved = registry.get("test_skill")
        assert retrieved is not None
        assert retrieved.metadata.name == "Test Skill"

    def test_unregister(self, sample_skill, registry):
        registry.register(sample_skill)
        registry.unregister("test_skill")
        assert registry.get("test_skill") is None

    def test_list(self, sample_skill, registry):
        registry.register(sample_skill)
        skills = registry.list()
        assert len(skills) >= 1

    def test_search_by_name(self, sample_skill, registry):
        registry.register(sample_skill)
        results = registry.search("Test")
        assert len(results) >= 1

    def test_search_by_tag(self, sample_skill, registry):
        registry.register(sample_skill)
        results = registry.search("test")
        assert len(results) >= 1

    def test_enable_disable(self, sample_skill, registry):
        registry.register(sample_skill)
        assert registry.get_enabled("test_skill") is not None
        registry.disable("test_skill")
        assert registry.get_enabled("test_skill") is None
        registry.enable("test_skill")
        assert registry.get_enabled("test_skill") is not None

    def test_health(self, sample_skill, registry):
        registry.register(sample_skill)
        health = registry.health()
        assert health["total"] >= 1
        assert health["enabled"] >= 1

    def test_count(self, sample_skill, registry):
        registry.register(sample_skill)
        assert registry.count() >= 1


# --- SkillExecutor Tests ---

class TestSkillExecutor:
    def test_execute_success(self, sample_skill):
        r = SkillRegistry()
        r.clear()
        r.register(sample_skill)
        executor = SkillExecutor(registry=r)
        result = executor.execute("test_skill", "http://example.com")
        assert result.status == SkillStatus.COMPLETED
        assert result.confidence == 0.9

    def test_execute_skill_not_found(self):
        executor = SkillExecutor()
        result = executor.execute("nonexistent", "http://example.com")
        assert result.status == SkillStatus.FAILED

    def test_execute_disabled_skill(self, sample_skill):
        r = SkillRegistry()
        r.clear()
        r.register(sample_skill)
        r.disable("test_skill")
        executor = SkillExecutor(registry=r)
        result = executor.execute("test_skill", "http://example.com")
        assert result.status == SkillStatus.FAILED

    def test_execute_caching(self, sample_skill):
        r = SkillRegistry()
        r.clear()
        r.register(sample_skill)
        cache = SkillCache()
        executor = SkillExecutor(registry=r, cache=cache)
        executor.execute("test_skill", "http://example.com")
        cached = cache.get("test_skill", "http://example.com")
        assert cached is not None

    def test_execute_telemetry_recorded(self, sample_skill):
        r = SkillRegistry()
        r.clear()
        r.register(sample_skill)
        telemetry = SkillTelemetry()
        executor = SkillExecutor(registry=r, telemetry=telemetry)
        executor.execute("test_skill", "http://example.com")
        stats = telemetry.get_stats("test_skill")
        assert stats["total_executions"] == 1

    def test_execute_with_context(self, sample_skill):
        r = SkillRegistry()
        r.clear()
        r.register(sample_skill)
        executor = SkillExecutor(registry=r)
        ctx = SkillContext(target="http://test.com", technologies=["Python"])
        result = executor.execute("test_skill", "http://example.com", context=ctx)
        assert result.status == SkillStatus.COMPLETED


# --- SkillPlanner Tests ---

class TestSkillPlanner:
    def test_plan_for_goal(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("tech_detection", [SkillCapability.TECHNOLOGY_DETECTION])
        planner = SkillPlanner()
        goal = Goal.create(GoalType.RECON, "Detect technology")
        skills = planner.plan_for_goal(goal)
        assert isinstance(skills, list)

    def test_plan_for_objective(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("lfi_skill", [SkillCapability.LFI])
        planner = SkillPlanner()
        skills = planner.plan_for_objective("Detect LFI vulnerability")
        assert isinstance(skills, list)

    def test_recommend_skills(self):
        SkillCapabilityRegistry.clear()
        SkillCapabilityRegistry.register("jwt_skill", [SkillCapability.JWT_ANALYSIS])
        planner = SkillPlanner()
        skills = planner.recommend_skills(["JWT", "Node.js"])
        assert isinstance(skills, list)


# --- SkillMarketplace Tests ---

class TestSkillMarketplace:
    def test_marketplace_stats(self):
        m = SkillMarketplace()
        stats = m.get_stats()
        assert "total_packages" in stats
        assert stats["total_packages"] >= 0

    def test_verify_nonexistent(self):
        m = SkillMarketplace()
        result = m.verify("nonexistent_skill")
        assert result["exists"] is False


# --- SkillContext Tests ---

class TestSkillContext:
    def test_default_context(self):
        ctx = SkillContext()
        assert ctx.target == ""
        assert ctx.technologies == []

    def test_to_dict(self):
        ctx = SkillContext(target="http://example.com", technologies=["Python"])
        d = ctx.to_dict()
        assert d["target"] == "http://example.com"
        assert d["technologies"] == ["Python"]


# --- Base Skill Tests ---

class TestBaseSkill:
    def test_abstract_class(self):
        with pytest.raises(TypeError):
            SecuritySkill()

    def test_concrete_skill(self, sample_skill):
        assert sample_skill.metadata.skill_id == "test_skill"
        assert sample_skill.metadata.name == "Test Skill"

    def test_skill_initialization(self, sample_skill):
        sample_skill.initialize()
        assert sample_skill._initialized is True

    def test_skill_execute_lifecycle(self, sample_skill):
        result = sample_skill.execute("http://example.com")
        assert result.status == SkillStatus.COMPLETED
        assert result.confidence == 0.9

    def test_skill_supports(self, sample_skill):
        assert sample_skill.supports("http://example.com") is True

    def test_skill_validate(self, sample_skill):
        assert sample_skill.validate("http://example.com") is None
        assert sample_skill.validate("") is not None

    def test_skill_verify(self, sample_skill):
        result = SkillResult.success("test", confidence=0.9)
        assert sample_skill.verify(result) is True

    def test_skill_estimate_cost(self, sample_skill):
        cost = sample_skill.estimate_cost("http://example.com")
        assert cost > 0

    def test_skill_estimate_duration(self, sample_skill):
        duration = sample_skill.estimate_duration("http://example.com")
        assert duration > 0

    def test_skill_risk_level(self, sample_skill):
        assert sample_skill.risk_level() == "low"

    def test_skill_to_dict(self, sample_skill):
        d = sample_skill.to_dict()
        assert d["skill_id"] == "test_skill"


# --- SkillLoader Tests ---

class TestSkillLoader:
    def test_discover_builtin(self):
        r = SkillRegistry()
        r.clear()
        loader = SkillLoader(r)
        count = loader.discover_builtin()
        assert count >= 1

    def test_load_from_path_invalid(self):
        loader = SkillLoader()
        skill = loader.load_from_path("/nonexistent/path.py")
        assert skill is None


# --- Default Skills Tests ---

class TestDefaultSkills:
    def test_all_default_skills_discoverable(self):
        r = SkillRegistry()
        r.clear()
        loader = SkillLoader(r)
        loader.discover_builtin()
        expected_skills = [
            "tech_detection", "http_header_analysis", "tls_analysis",
            "cookie_analysis", "auth_analysis", "jwt_analysis",
            "oauth_analysis", "cors_analysis", "csp_analysis",
            "csrf_detection", "clickjacking_analysis", "open_redirect",
            "directory_enumeration", "file_upload_analysis", "lfi_detection",
            "rfi_detection", "ssrf_detection", "xxe_detection",
            "ssti_detection", "sql_injection", "nosql_injection",
            "command_injection", "path_traversal", "deserialization_analysis",
            "graphql_analysis", "websocket_analysis", "rest_api_analysis",
            "openapi_analysis", "grpc_discovery", "dns_intelligence",
            "subdomain_enumeration", "waf_fingerprinting",
            "fingerprint_correlation", "secrets_detection", "cloud_metadata",
            "s3_analysis", "azure_blob_analysis", "gcp_storage_analysis",
            "kubernetes_detection", "docker_analysis", "ci_cd_secrets",
        ]
        for sid in expected_skills:
            skill = r.get(sid)
            assert skill is not None, f"Default skill not found: {sid}"

    def test_technology_detection_skill(self):
        from core.skills.plugins import TechnologyDetectionSkill
        skill = TechnologyDetectionSkill()
        assert SkillCapability.TECHNOLOGY_DETECTION in skill.capabilities

    def test_http_header_analysis_skill(self):
        from core.skills.plugins import HTTPHeaderAnalysisSkill
        skill = HTTPHeaderAnalysisSkill()
        assert SkillCapability.HTTP_HEADER_ANALYSIS in skill.capabilities

    def test_lfi_detection_skill(self):
        from core.skills.plugins import LFIDetectionSkill
        skill = LFIDetectionSkill()
        assert SkillCapability.LFI in skill.capabilities

    def test_sql_injection_skill(self):
        from core.skills.plugins import SQLInjectionSkill
        skill = SQLInjectionSkill()
        assert SkillCapability.SQL_INJECTION in skill.capabilities

    def test_ssrf_detection_skill(self):
        from core.skills.plugins import SSRFDetectionSkill
        skill = SSRFDetectionSkill()
        assert SkillCapability.SSRF in skill.capabilities

    def test_jwt_analysis_skill(self):
        from core.skills.plugins import JWTAnalysisSkill
        skill = JWTAnalysisSkill()
        assert SkillCapability.JWT_ANALYSIS in skill.capabilities

    def test_graphql_analysis_skill(self):
        from core.skills.plugins import GraphQLAnalysisSkill
        skill = GraphQLAnalysisSkill()
        assert SkillCapability.GRAPHQL in skill.capabilities

    def test_waf_fingerprinting_skill(self):
        from core.skills.plugins import WAFFingerprintingSkill
        skill = WAFFingerprintingSkill()
        assert SkillCapability.WAF_FINGERPRINT in skill.capabilities

    def test_secrets_detection_skill(self):
        from core.skills.plugins import SecretsDetectionSkill
        skill = SecretsDetectionSkill()
        assert SkillCapability.SECRETS_DETECTION in skill.capabilities

    def test_cloud_metadata_skill(self):
        from core.skills.plugins import CloudMetadataSkill
        skill = CloudMetadataSkill()
        assert SkillCapability.CLOUD_METADATA in skill.capabilities

    def test_skill_execution(self):
        from core.skills.plugins import TechnologyDetectionSkill
        skill = TechnologyDetectionSkill()
        result = skill.execute("http://example.com")
        assert result.status == SkillStatus.COMPLETED
        assert result.confidence >= 0.5
        assert len(result.findings) > 0

    def test_default_skill_metadata(self):
        from core.skills.plugins import TechnologyDetectionSkill
        skill = TechnologyDetectionSkill()
        m = skill.metadata
        assert m.skill_id == "tech_detection"
        assert m.name is not None
        assert m.version is not None
        assert m.risk_level is not None
        assert m.noise_level is not None
