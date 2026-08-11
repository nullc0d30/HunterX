# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool selection engine.

Ranks candidate tools against a set of selection criteria: mission profile,
target type, available inputs, execution time, historical accuracy,
reliability, installed status, performance, dependencies and user
preferences. Produces scored, ordered results.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolSelectionError
from hunterx.domain.tool_intelligence import (
    ToolMetadata,
    ToolSelectionCriteria,
    ToolSelectionResult,
    ToolState,
)
from hunterx.tools.intelligence.compatibility import CompatibilityEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.vocabulary import CapabilityVocabulary


class ToolSelectionEngine:
    """Score and rank tools against :class:`ToolSelectionCriteria`.

    Scoring is additive and normalized to ``[0, 1]``. A tool with a missing
    required capability is excluded. ``require_installed`` excludes tools whose
    runtime state is not ``AVAILABLE``. When a :class:`CapabilityVocabulary`
    is provided, capability matching is canonical — ``subdomain-discovery``
    matches a tool that advertises ``subdomain-enumeration``.
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        compatibility: CompatibilityEngine,
        vocabulary: CapabilityVocabulary | None = None,
    ) -> None:
        self._registry = registry
        self._compatibility = compatibility
        self._vocabulary = vocabulary or CapabilityVocabulary()

    def select(self, criteria: ToolSelectionCriteria) -> list[ToolSelectionResult]:
        """Return ranked selection results for ``criteria``, best first.

        Raises:
            ToolSelectionError: if no tool matches the criteria.

        """
        candidates = self._registry.list_metadata()
        if not candidates:
            raise ToolSelectionError("no tools are registered")

        scored: list[ToolSelectionResult] = []
        for metadata in candidates:
            result = self._score(metadata, criteria)
            if result is not None:
                scored.append(result)

        scored.sort(key=lambda item: item.score, reverse=True)
        if not scored:
            raise ToolSelectionError(
                "no tool satisfies the given criteria (required capabilities "
                "or environment constraints)"
            )
        return scored[: criteria.limit]

    def _score(
        self,
        metadata: ToolMetadata,
        criteria: ToolSelectionCriteria,
    ) -> ToolSelectionResult | None:
        score = 0.0
        reasons: list[str] = []
        capabilities = self._registry.capabilities_for(metadata.tool_id)

        required = set(criteria.required_capabilities)
        if required:
            required_canonical = {self._vocabulary.canonical(item) for item in required}
            tool_canonical = {self._vocabulary.canonical(item) for item in capabilities}
            if not required_canonical.issubset(tool_canonical):
                return None
            score += 2.0
            reasons.append("provides required capabilities")

        if criteria.require_installed:
            state = self._registry.get_state(metadata.tool_id)
            if state is None or state.state != ToolState.AVAILABLE:
                return None
            score += 1.0
            reasons.append("installed and available")

        if criteria.mission_profile:
            knowledge = self._registry.get_knowledge(metadata.tool_id)
            if (
                knowledge is not None
                and criteria.mission_profile not in knowledge.supported_mission_profiles
            ):
                return None
            score += 1.0
            reasons.append(f"supports mission '{criteria.mission_profile}'")

        if criteria.target_type:
            knowledge = self._registry.get_knowledge(metadata.tool_id)
            if knowledge is not None and knowledge.inputs:
                accepts = set(knowledge.inputs.accepts) | set(knowledge.inputs.required)
                if criteria.target_type not in accepts:
                    return None
                score += 1.0
                reasons.append(f"accepts target type '{criteria.target_type}'")

        if criteria.available_inputs:
            knowledge = self._registry.get_knowledge(metadata.tool_id)
            if knowledge is not None:
                required_inputs = set(knowledge.inputs.required)
                if required_inputs and not required_inputs.issubset(
                    set(criteria.available_inputs)
                ):
                    return None

        if criteria.max_execution_time_s > 0:
            performance = self._registry.get_performance(metadata.tool_id)
            if (
                performance is not None
                and performance.average_duration_ms / 1000.0 > criteria.max_execution_time_s
            ):
                return None

        # Environment compatibility.
        compatibility = self._compatibility.check(
            metadata.tool_id,
            os_name=criteria.os,
            architecture=criteria.architecture,
            air_gapped=criteria.air_gapped,
            cloud=criteria.cloud,
        )
        if not compatibility.compatible:
            return None
        if compatibility.missing:
            score -= 0.5 * len(compatibility.missing)
            reasons.extend(f"missing: {item}" for item in compatibility.missing)

        # Reliability and performance signals.
        health = self._registry.get_health(metadata.tool_id)
        if health is not None:
            score += health.reliability_score
            reasons.append(f"reliability {health.reliability_score:.2f}")

        performance = self._registry.get_performance(metadata.tool_id)
        if performance is not None:
            score += performance.success_rate * 0.5
            score -= performance.false_positive_rate * 0.5
            score -= performance.failure_rate * 0.3
            if performance.average_duration_ms:
                score -= min(1.0, performance.average_duration_ms / 600_000.0) * 0.2
            reasons.append("performance considered")

        # Community/adoption signal.
        score += min(1.0, metadata.community_score / 100.0) * 0.5

        if metadata.tool_id in criteria.preferences:
            score += 1.0
            reasons.append("user preferred")

        score = max(0.0, min(5.0, score)) / 5.0
        return ToolSelectionResult(
            tool_id=metadata.tool_id,
            score=score,
            reasons=tuple(reasons),
        )
