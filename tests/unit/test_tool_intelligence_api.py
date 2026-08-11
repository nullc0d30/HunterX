# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the TIP facade, validation, docs generator, schema and AI bridge."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolNotFoundError
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort
from hunterx.domain.tool_intelligence import (
    ToolCompatibility,
    ToolDependency,
    ToolKnowledge,
    ToolMetadata,
    ToolSelectionCriteria,
)
from hunterx.tools.intelligence.ai import ToolAIInterface, build_recommendation_prompt
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.schema import (
    compatibility_from_dict,
    knowledge_from_dict,
    metadata_from_dict,
    metadata_to_dict,
)
from hunterx.tools.intelligence.validation import ValidationReport, ValidationSeverity
from tests.framework.tip import (
    make_compatibility,
    make_knowledge,
    make_metadata,
    register_standard_tools,
)


def _tip() -> ToolIntelligenceAPI:
    tip = ToolIntelligenceAPI()
    register_standard_tools(tip)
    return tip


class TestFacade:
    def test_implements_port(self) -> None:
        tip = _tip()
        assert isinstance(tip, ToolIntelligencePort)

    def test_register_and_query(self) -> None:
        tip = _tip()
        assert tip.get_tool("katana") is not None
        assert tip.get_tool("nope") is None
        assert {m.tool_id for m in tip.list_tools()} == {"katana", "nmap", "httpx", "ffuf"}
        assert {m.tool_id for m in tip.search_tools("crawl")} == {"katana"}
        assert tip.get_knowledge("katana").capabilities == ("web-crawling", "http-enumeration")

    def test_capabilities_and_taxonomy(self) -> None:
        tip = _tip()
        assert "web-crawling" in tip.capabilities()
        assert tip.taxonomy().id == "root"
        assert tip.tools_by_capability("web-crawling") == ["katana"]
        matches = tip.search_capabilities("fuzz")
        assert any(c.capability_id == "web-fuzzing" for c in matches)

    def test_registration_errors(self) -> None:
        tip = _tip()
        with pytest.raises(Exception):
            tip.register_tool(make_metadata("katana"))

    def test_unregister(self) -> None:
        tip = _tip()
        tip.unregister("nmap")
        assert tip.get_tool("nmap") is None
        with pytest.raises(ToolNotFoundError):
            tip.unregister("nmap")

    def test_compatibility_and_validation_wrappers(self) -> None:
        tip = _tip()
        profile = tip.check_compatibility("katana", os_name="linux")
        assert isinstance(profile, ToolCompatibility)
        report = tip.compatibility_report("katana", os_name="linux")
        assert report.compatible is True
        with pytest.raises(ToolNotFoundError):
            tip.compatibility_report("nope", os_name="linux")

    def test_health_performance_records(self) -> None:
        tip = _tip()
        tip.record_success("katana", duration_ms=200)
        tip.record_failure("katana", crash=True)
        assert tip.health("katana").samples == 2
        tip.record_performance("katana", duration_ms=200, findings=5)
        assert tip.performance("katana").samples == 1

    def test_generate_docs_raises_for_unknown(self) -> None:
        tip = _tip()
        with pytest.raises(ToolNotFoundError):
            tip.generate_docs("nope")

    def test_validate_raises_for_unknown(self) -> None:
        tip = _tip()
        with pytest.raises(ToolNotFoundError):
            tip.validate("nope")


class TestValidation:
    def test_valid_registration_passes(self) -> None:
        tip = _tip()
        report = tip.validate("katana")
        assert isinstance(report, ValidationReport)
        assert report.valid

    def test_missing_knowledge_dependency_is_error(self) -> None:
        tip = ToolIntelligenceAPI()
        tip.register_tool(
            make_metadata("lone"),
            knowledge=make_knowledge(
                "lone",
                capabilities=("custom-thing",),
                dependencies=(
                    ToolDependency(capability="ghost-capability", optional=False),
                ),
            ),
            compatibility=make_compatibility("lone"),
        )
        report = tip.validate("lone")
        assert not report.valid
        assert any(f.check == "dependencies" for f in report.errors())

    def test_optional_dependency_is_warning(self) -> None:
        tip = ToolIntelligenceAPI()
        tip.register_tool(
            make_metadata("lone"),
            knowledge=make_knowledge(
                "lone",
                capabilities=("custom-thing",),
                dependencies=(
                    ToolDependency(capability="ghost-capability", optional=True),
                ),
            ),
            compatibility=make_compatibility("lone"),
        )
        report = tip.validate("lone")
        assert report.valid
        assert any(
            f.severity == ValidationSeverity.WARNING and f.check == "dependencies"
            for f in report.findings
        )

    def test_validate_mapping(self) -> None:
        tip = _tip()
        report = tip.validation.validate_mapping({"tool_id": "x"})
        assert report.valid
        bad = tip.validation.validate_mapping({})
        assert not bad.valid


class TestDocumentationGenerator:
    def test_generate_contains_metadata_and_knowledge(self) -> None:
        tip = _tip()
        markdown = tip.generate_docs("katana")
        assert markdown.startswith("# Katana")
        assert "## Metadata" in markdown
        assert "## Knowledge" in markdown
        assert "web-crawling" in markdown
        assert markdown.endswith("\n")

    def test_generate_all(self) -> None:
        tip = _tip()
        docs = tip.docs.generate_all()
        assert set(docs) == {"katana", "nmap", "httpx", "ffuf"}


class TestSchema:
    def test_metadata_roundtrip(self) -> None:
        metadata = make_metadata("katana", tags=("crawler",))
        restored = metadata_from_dict(metadata_to_dict(metadata))
        assert restored == metadata

    def test_knowledge_roundtrip(self) -> None:
        from dataclasses import asdict

        knowledge = make_knowledge(
            "katana",
            capabilities=("web-crawling",),
            accepts=("url",),
            required_inputs=("url",),
        )
        restored = knowledge_from_dict(asdict(knowledge))
        assert restored.tool_id == knowledge.tool_id
        assert restored.inputs.required == ("url",)

    def test_compatibility_from_dict(self) -> None:
        from dataclasses import asdict

        compatibility = make_compatibility("katana", docker=True, cloud=False)
        restored = compatibility_from_dict(asdict(compatibility))
        assert restored == compatibility


class TestAIInterface:
    def _ai(self) -> ToolAIInterface:
        tip = _tip()
        tip.install("katana")
        tip.verify("katana")
        tip.make_available("katana")
        return ToolAIInterface(tip.registry, tip.selection)

    def test_which_tool(self) -> None:
        answer = self._ai().which_tool("web-crawling")
        assert answer.question == "which-tool"
        assert "katana" in answer.tool_ids

    def test_which_tool_unknown(self) -> None:
        answer = self._ai().which_tool("ghost-capability")
        assert answer.question == "which-tool"
        assert answer.tool_ids == ()

    def test_required_inputs(self) -> None:
        answer = self._ai().required_inputs("katana")
        assert answer.question == "required-inputs"
        assert answer.data["required"] == ["url"]

    def test_expected_outputs(self) -> None:
        answer = self._ai().expected_outputs("katana")
        assert answer.question == "expected-outputs"
        assert "json" in answer.data["formats"]

    def test_why(self) -> None:
        answer = self._ai().why("katana")
        assert answer.question == "why"
        assert answer.tool_ids == ("katana",)
        assert "katana" in answer.text

    def test_what_next_empty_without_downstream(self) -> None:
        answer = self._ai().what_next("katana")
        assert answer.question == "what-next"
        assert answer.tool_ids == ()

    def test_better_tool_exists(self) -> None:
        answer = self._ai().better_tool("web-crawling", "nmap")
        assert answer.question == "better-tool"
        assert answer.tool_ids[0] == "katana"

    def test_better_tool_is_current(self) -> None:
        answer = self._ai().better_tool("web-crawling", "katana")
        assert answer.question == "better-tool"
        assert "already the best" in answer.text

    def test_combine(self) -> None:
        tip = _tip()
        results = tip.select(
            ToolSelectionCriteria(required_capabilities=("http-enumeration",), require_installed=False)
        )
        answer = self._ai().combine("http-enumeration", results)
        assert answer.question == "combine"
        assert len(answer.tool_ids) > 1

    def test_build_recommendation_prompt(self) -> None:
        tip = _tip()
        recommendations = tip.recommend("http-enumeration")
        prompt = build_recommendation_prompt("http-enumeration", recommendations)
        assert "http-enumeration" in prompt
        assert "best" in prompt


class TestStandaloneEngines:
    def test_registry_injection_into_facade(self) -> None:
        registry = ToolIntelligenceRegistry()
        tip = ToolIntelligenceAPI(registry)
        tip.register_tool(make_metadata("katana"))
        assert tip.registry is registry
        assert tip.get_tool("katana") is not None

    def test_knowledge_roundtrip_through_facade(self) -> None:
        tip = ToolIntelligenceAPI()
        knowledge = make_knowledge("katana", capabilities=("web-crawling",))
        tip.register_tool(make_metadata("katana"), knowledge=knowledge)
        assert tip.get_knowledge("katana") == knowledge

    def test_metadata_type(self) -> None:
        tip = ToolIntelligenceAPI()
        tip.register_tool(make_metadata("katana"))
        assert isinstance(tip.get_tool("katana"), ToolMetadata)
        assert isinstance(tip.get_knowledge("katana"), ToolKnowledge) or tip.get_knowledge("katana") is None
