# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool recommendation engine.

Recommends the best tool, an alternative, a fallback, complementary tools, a
replacement for deprecated tools, and flags deprecated providers. Combines
selection scores, capability knowledge and reliability signals.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    RecommendationKind,
    ToolRecommendation,
    ToolSelectionResult,
    ToolState,
)
from hunterx.tools.intelligence.dependency import DependencyEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionCriteria, ToolSelectionEngine
from hunterx.tools.intelligence.vocabulary import CapabilityVocabulary


class ToolRecommendationEngine:
    """Produce structured recommendations for a capability need.

    Recommendations are ordered: best, alternative, fallback, complementary.
    Deprecated providers are surfaced with :attr:`RecommendationKind.DEPRECATED`.
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        selection: ToolSelectionEngine,
        dependency: DependencyEngine,
        vocabulary: CapabilityVocabulary | None = None,
    ) -> None:
        self._registry = registry
        self._selection = selection
        self._dependency = dependency
        self._vocabulary = vocabulary or CapabilityVocabulary()

    def recommend(self, capability_id: str, *, preferences: tuple[str, ...] = ()) -> list[ToolRecommendation]:
        """Return recommendations for ``capability_id``.

        Provider lookup is vocabulary-aware: ``xss-detection`` also matches
        tools advertising ``xss-discovery``. If no tool can provide the
        capability, an empty list is returned.
        """
        providers = self._providers_for(capability_id)
        if not providers:
            return []

        criteria = ToolSelectionCriteria(
            required_capabilities=(capability_id,),
            require_installed=False,
            preferences=preferences,
            limit=20,
        )
        scored = self._selection.select(criteria)

        recommendations: list[ToolRecommendation] = []
        best: ToolSelectionResult | None = scored[0] if scored else None
        for index, result in enumerate(scored):
            state = self._registry.get_state(result.tool_id)
            if state is not None and state.state == ToolState.DEPRECATED:
                kind = RecommendationKind.DEPRECATED
            elif index == 0 and best is not None and result.tool_id == best.tool_id:
                kind = RecommendationKind.BEST
            elif index == 1:
                kind = RecommendationKind.ALTERNATIVE
            else:
                kind = RecommendationKind.FALLBACK
            recommendations.append(
                ToolRecommendation(
                    tool_id=result.tool_id,
                    kind=kind,
                    score=result.score,
                    reason="; ".join(result.reasons) if result.reasons else "",
                )
            )

        if best is not None:
            for complementary in self._complementary(best.tool_id):
                recommendations.append(
                    ToolRecommendation(
                        tool_id=complementary,
                        kind=RecommendationKind.COMPLEMENTARY,
                        score=best.score * 0.9,
                        reason="complements the best tool for this capability",
                    )
                )

        return recommendations

    def replacement_for(self, tool_id: str) -> list[ToolRecommendation]:
        """Return replacement recommendations for a deprecated ``tool_id``.

        Replacements are tools that provide the same capabilities as
        ``tool_id`` (excluding ``tool_id`` itself).
        """
        capabilities = self._registry.capabilities_for(tool_id)
        state = self._registry.get_state(tool_id)
        if state is None or state.state != ToolState.DEPRECATED:
            return []

        replacements: list[ToolRecommendation] = []
        for capability_id in capabilities:
            for provider in self._providers_for(capability_id):
                if provider == tool_id:
                    continue
                replacements.append(
                    ToolRecommendation(
                        tool_id=provider,
                        kind=RecommendationKind.REPLACEMENT,
                        score=0.8,
                        reason=f"replaces '{tool_id}' for '{capability_id}'",
                    )
                )
        seen: set[str] = set()
        deduped: list[ToolRecommendation] = []
        for recommendation in replacements:
            if recommendation.tool_id in seen:
                continue
            seen.add(recommendation.tool_id)
            deduped.append(recommendation)
        return deduped

    def deprecated_providers(self, capability_id: str) -> list[ToolRecommendation]:
        """Return deprecated tools that still provide ``capability_id``."""
        deprecated: list[ToolRecommendation] = []
        for provider in self._providers_for(capability_id):
            state = self._registry.get_state(provider)
            if state is not None and state.state == ToolState.DEPRECATED:
                deprecated.append(
                    ToolRecommendation(
                        tool_id=provider,
                        kind=RecommendationKind.DEPRECATED,
                        score=0.0,
                        reason=f"deprecated but provides '{capability_id}'",
                    )
                )
        return deprecated

    def _providers_for(self, capability_id: str) -> list[str]:
        """Return providers for ``capability_id`` across the vocabulary."""
        canonical = self._vocabulary.canonical(capability_id)
        providers: set[str] = set(self._registry.providers_for(capability_id))
        providers.update(self._registry.providers_for(canonical))
        for variant in self._vocabulary.variants(canonical):
            providers.update(self._registry.providers_for(variant))
        return sorted(providers)

    def _complementary(self, tool_id: str) -> list[str]:
        """Return tools that cover the prerequisite capabilities of ``tool_id``."""
        complements: list[str] = []
        seen: set[str] = set()
        for prerequisite in self._dependency.resolve_dependencies(tool_id):
            if prerequisite not in seen:
                seen.add(prerequisite)
                complements.append(prerequisite)
        return complements
