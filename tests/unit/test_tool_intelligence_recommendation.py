# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the recommendation engine."""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    RecommendationKind,
    ToolDependency,
    ToolRecommendation,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from tests.framework.tip import make_compatibility, make_knowledge, make_metadata, register_standard_tools


def _tip() -> ToolIntelligenceAPI:
    tip = ToolIntelligenceAPI()
    register_standard_tools(tip)
    return tip


class TestRecommendation:
    def test_recommend_returns_best_alternative_fallback(self) -> None:
        tip = _tip()
        recommendations = tip.recommend("http-enumeration")
        assert isinstance(recommendations, list)
        assert recommendations
        assert all(isinstance(r, ToolRecommendation) for r in recommendations)
        assert recommendations[0].kind == RecommendationKind.BEST
        assert recommendations[0].tool_id == "katana"
        assert recommendations[1].kind == RecommendationKind.ALTERNATIVE

    def test_recommend_unknown_capability_is_empty(self) -> None:
        tip = _tip()
        assert tip.recommend("ghost-capability") == []

    def test_deprecated_provider_flagged(self) -> None:
        tip = _tip()
        tip.deprecate("httpx")
        recommendations = tip.recommend("http-enumeration")
        deprecated = [r for r in recommendations if r.kind == RecommendationKind.DEPRECATED]
        assert any(r.tool_id == "httpx" for r in deprecated)

    def test_complementary_dependencies_appended(self) -> None:
        tip = _tip()
        tip.register_tool(
            make_metadata("wpscan", category="assessment", subcategory="web"),
            knowledge=make_knowledge(
                "wpscan",
                capabilities=("vulnerability-scan",),
                accepts=("url",),
                required_inputs=("url",),
                dependencies=(ToolDependency(capability="web-crawling", provided_by="katana"),),
            ),
            compatibility=make_compatibility("wpscan"),
        )
        recommendations = tip.recommend("vulnerability-scan")
        complementary = [r for r in recommendations if r.kind == RecommendationKind.COMPLEMENTARY]
        assert any(r.tool_id == "katana" for r in complementary)

    def test_replacement_for_deprecated(self) -> None:
        tip = _tip()
        tip.register_tool(
            make_metadata("old-crawler"),
            knowledge=make_knowledge(
                "old-crawler",
                capabilities=("web-crawling",),
                accepts=("url",),
                required_inputs=("url",),
            ),
            compatibility=make_compatibility("old-crawler"),
        )
        tip.deprecate("old-crawler")
        replacements = tip.recommendations.replacement_for("old-crawler")
        assert any(r.kind == RecommendationKind.REPLACEMENT for r in replacements)
        assert all(r.tool_id != "old-crawler" for r in replacements)

    def test_replacement_requires_deprecated_state(self) -> None:
        tip = _tip()
        assert tip.recommendations.replacement_for("katana") == []

    def test_deprecated_providers_listing(self) -> None:
        tip = _tip()
        tip.deprecate("katana")
        deprecated = tip.recommendations.deprecated_providers("web-crawling")
        assert [r.tool_id for r in deprecated] == ["katana"]
        assert all(r.kind == RecommendationKind.DEPRECATED for r in deprecated)

    def test_preferences_influence_recommendation(self) -> None:
        tip = _tip()
        recommendations = tip.recommendations.recommend("http-enumeration", preferences=("httpx",))
        assert recommendations[0].tool_id == "httpx"
