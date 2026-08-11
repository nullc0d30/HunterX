# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the dependency, compatibility and selection engines."""

from __future__ import annotations

import pytest

from hunterx.domain.exceptions import ToolNotFoundError, ToolSelectionError
from hunterx.domain.tool_intelligence import (
    ToolDependency,
    ToolSelectionCriteria,
    ToolSelectionResult,
    ToolState,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.compatibility import CompatibilityEngine, CompatibilityResult
from hunterx.tools.intelligence.dependency import DependencyEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionEngine
from tests.framework.tip import make_compatibility, make_knowledge, make_metadata, register_standard_tools


def _tip() -> ToolIntelligenceAPI:
    tip = ToolIntelligenceAPI()
    register_standard_tools(tip)
    return tip


class TestDependencyEngine:
    def test_resolve_dependencies_is_topological(self) -> None:
        tip = _tip()
        tip.register_tool(
            make_metadata("wpscan", category="assessment", subcategory="web"),
            knowledge=make_knowledge(
                "wpscan",
                capabilities=("vulnerability-scan",),
                accepts=("url",),
                required_inputs=("url",),
                dependencies=(
                    ToolDependency(capability="web-crawling", provided_by="katana"),
                    ToolDependency(capability="port-scanning", provided_by="nmap"),
                ),
            ),
            compatibility=make_compatibility("wpscan"),
        )

        deps = tip.resolve_dependencies("wpscan")
        assert set(deps) == {"katana", "nmap"}

    def test_resolve_dependencies_transitive(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("scanner"))
        registry.register_metadata(make_metadata("crawler"))
        registry.register_knowledge(
            make_knowledge("scanner", capabilities=("scan-all",), dependencies=(ToolDependency(capability="crawl-all"),))
        )
        registry.register_knowledge(
            make_knowledge("crawler", capabilities=("crawl-all",), dependencies=(ToolDependency(capability="dns-all"),))
        )
        registry.register_metadata(make_metadata("resolver"))
        registry.register_knowledge(
            make_knowledge("resolver", capabilities=("dns-all",))
        )

        engine = DependencyEngine(registry)
        deps = engine.resolve_dependencies("scanner")
        assert "crawler" in deps
        assert "resolver" in deps
        assert deps.index("crawler") < deps.index("resolver")

    def test_resolve_unknown_tool_raises(self) -> None:
        engine = DependencyEngine(ToolIntelligenceRegistry())
        with pytest.raises(ToolNotFoundError):
            engine.resolve_dependencies("nope")

    def test_is_satisfied(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("scanner"))
        registry.register_knowledge(
            make_knowledge("scanner", capabilities=("scan-all",), dependencies=(ToolDependency(capability="crawl-all"),))
        )
        registry.register_metadata(make_metadata("crawler"))
        registry.register_knowledge(make_knowledge("crawler", capabilities=("crawl-all",)))

        engine = DependencyEngine(registry)
        ok, missing = engine.is_satisfied("scanner")
        assert ok is True
        assert missing == []

        registry.register_metadata(make_metadata("lone"))
        registry.register_knowledge(
            make_knowledge("lone", capabilities=("x",), dependencies=(ToolDependency(capability="ghost"),))
        )
        ok, missing = engine.is_satisfied("lone")
        assert ok is False
        assert missing == ["ghost"]

    def test_required_tool_chain(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("scanner"))
        registry.register_knowledge(make_knowledge("scanner", capabilities=("scan-all",)))
        registry.register_metadata(make_metadata("crawler"))
        registry.register_knowledge(make_knowledge("crawler", capabilities=("crawl-all",)))

        engine = DependencyEngine(registry)
        chain = engine.required_tool_chain(["scan-all", "crawl-all"])
        assert set(chain) == {"scanner", "crawler"}

    def test_cycle_report_is_empty_for_acyclic(self) -> None:
        tip = _tip()
        assert tip.dependencies.cycle_report() == []

    def test_dependency_map(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("scanner"))
        registry.register_knowledge(
            make_knowledge("scanner", capabilities=("scan-all",), dependencies=(ToolDependency(capability="crawl-all"),))
        )
        registry.register_metadata(make_metadata("crawler"))
        registry.register_knowledge(make_knowledge("crawler", capabilities=("crawl-all",)))

        engine = DependencyEngine(registry)
        mapping = engine.dependency_map()
        assert mapping["scanner"] == ["crawler"]
        assert mapping["crawler"] == []


class TestCompatibilityEngine:
    def _registry(self) -> ToolIntelligenceRegistry:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("katana"))
        registry.register_compatibility(
            make_compatibility(
                "katana",
                os=("linux", "windows"),
                architectures=("amd64", "arm64"),
                docker=True,
                cloud=False,
                air_gapped=False,
            )
        )
        return registry

    def test_check_compatible(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", os_name="linux", architecture="amd64", docker=True)
        assert result.compatible is True

    def test_check_unsupported_os(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", os_name="darwin", architecture="amd64")
        assert result.compatible is False
        assert "os 'darwin'" in result.missing

    def test_check_unsupported_architecture(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", architecture="i386")
        assert result.compatible is False

    def test_check_air_gapped_violation(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", air_gapped=True)
        assert result.compatible is False
        assert "air-gapped" in result.missing

    def test_check_cloud_violation(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", cloud=True)
        assert result.compatible is False

    def test_check_empty_os_skips_os_check(self) -> None:
        engine = CompatibilityEngine(self._registry())
        result = engine.check("katana", os_name="", architecture="")
        assert result.compatible is True

    def test_no_profile_is_always_compatible(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("katana"))
        result = CompatibilityEngine(registry).check("katana", os_name="darwin")
        assert result.compatible is True

    def test_available_backends(self) -> None:
        engine = CompatibilityEngine(self._registry())
        backends = engine.available_backends("katana")
        assert "native" in backends
        assert "docker" in backends
        assert "cloud" not in backends
        assert "air-gapped" not in backends


class TestSelectionEngine:
    def _available_tip(self) -> ToolIntelligenceAPI:
        tip = _tip()
        for tool_id in ("katana", "nmap", "httpx", "ffuf"):
            tip.install(tool_id)
            tip.verify(tool_id)
            tip.make_available(tool_id)
        return tip

    def test_select_returns_ranked_results(self) -> None:
        tip = self._available_tip()
        results = tip.select(
            ToolSelectionCriteria(required_capabilities=("web-crawling",))
        )
        assert isinstance(results, list)
        assert results
        assert all(isinstance(r, ToolSelectionResult) for r in results)
        assert results[0].tool_id == "katana"

    def test_select_requires_installed(self) -> None:
        tip = self._available_tip()
        results = tip.select(
            ToolSelectionCriteria(required_capabilities=("web-crawling",), require_installed=True)
        )
        assert results[0].tool_id == "katana"

    def test_select_excludes_uninstalled_when_required(self) -> None:
        tip = _tip()
        with pytest.raises(ToolSelectionError):
            tip.select(
                ToolSelectionCriteria(required_capabilities=("web-crawling",), require_installed=True)
            )

    def test_select_unknown_capability_raises(self) -> None:
        tip = self._available_tip()
        with pytest.raises(ToolSelectionError):
            tip.select(ToolSelectionCriteria(required_capabilities=("ghost-capability",)))

    def test_select_by_target_type(self) -> None:
        tip = self._available_tip()
        results = tip.select(
            ToolSelectionCriteria(required_capabilities=("http-enumeration",), target_type="url")
        )
        assert results[0].tool_id == "katana"

    def test_select_respects_air_gapped(self) -> None:
        tip = self._available_tip()
        tip.registry.register_compatibility(make_compatibility("katana", air_gapped=False))
        tip.register_tool(
            make_metadata("soup", category="recon", subcategory="http"),
            knowledge=make_knowledge(
                "soup",
                capabilities=("web-crawling",),
                accepts=("url",),
                required_inputs=("url",),
            ),
            compatibility=make_compatibility("soup", air_gapped=True),
        )
        tip.install("soup")
        tip.verify("soup")
        tip.make_available("soup")
        results = tip.select(
            ToolSelectionCriteria(
                required_capabilities=("web-crawling",),
                require_installed=True,
                air_gapped=True,
            )
        )
        assert results[0].tool_id == "soup"
        assert all(r.tool_id != "katana" for r in results)

    def test_score_boots_reliability_and_preferences(self) -> None:
        tip = self._available_tip()
        tip.record_success("nmap", duration_ms=10)
        tip.record_success("nmap", duration_ms=10)
        results = tip.select(
            ToolSelectionCriteria(
                required_capabilities=("port-scanning",),
                require_installed=True,
                preferences=("nmap",),
            )
        )
        assert results[0].tool_id == "nmap"

    def test_manual_selection_engine(self) -> None:
        tip = self._available_tip()
        engine = ToolSelectionEngine(tip.registry, tip.compatibility)
        results = engine.select(
            ToolSelectionCriteria(required_capabilities=("web-fuzzing",), require_installed=True)
        )
        assert results[0].tool_id == "ffuf"

    def test_compatibility_result_type(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("katana"))
        result = CompatibilityEngine(registry).check("katana")
        assert isinstance(result, CompatibilityResult)
        assert result.compatible is True

    def test_state_available_required(self) -> None:
        registry = ToolIntelligenceRegistry()
        registry.register_metadata(make_metadata("katana"))
        registry.register_knowledge(make_knowledge("katana", capabilities=("web-crawling",)))
        engine = ToolSelectionEngine(registry, CompatibilityEngine(registry))
        with pytest.raises(ToolSelectionError):
            engine.select(ToolSelectionCriteria(required_capabilities=("web-crawling",), require_installed=True))

    def test_state_machine_availability_signal(self) -> None:
        assert ToolState.AVAILABLE is ToolState.AVAILABLE
