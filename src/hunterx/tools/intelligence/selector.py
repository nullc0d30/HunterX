# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Selector (Sprint 023).

The ToolSelector extends the classic :class:`ToolSelectionEngine` with the
Sprint 023 knowledge contracts. Where the classic engine returns a bare score,
the selector produces a full :class:`ToolSelection` that captures *why* a tool
was chosen — required inputs, expected outputs, expected evidence, proof
capability, confidence ceiling, safety class and estimated cost.

Invariants enforced here:

- A tool whose ``safety_class`` exceeds the authorization ceiling is never
  selected.
- A tool is never selected for a vulnerability class it cannot evidence.
- ``expected_evidence`` and ``confidence_ceiling`` come from the tool's
  evidence mappings / confidence ceiling, never from raw output.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolSelectionError
from hunterx.domain.tool_intelligence import (
    EvidenceStrength,
    ToolEvidenceMapping,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolSelection,
    ToolSelectionCriteria,
    ToolSelectionResult,
)
from hunterx.tools.intelligence.compatibility import CompatibilityEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionEngine


class ToolSelector:
    """Sprint 023 selection: ranked, safety-aware :class:`ToolSelection`.

    Usage::

        selector = ToolSelector(registry, compatibility)
        selections = selector.select(criteria, authorization=ToolSafetyClass.ACTIVE)
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        compatibility: CompatibilityEngine,
        base: ToolSelectionEngine | None = None,
    ) -> None:
        self._registry = registry
        self._compatibility = compatibility
        self._base = base or ToolSelectionEngine(registry, compatibility)

    def select(
        self,
        criteria: ToolSelectionCriteria,
        *,
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
        mission_scope: str = "",
        authorization_granted: bool = False,
    ) -> list[ToolSelection]:
        """Return ranked, safety-aware selections for ``criteria``.

        ``authorization`` is the mission/target safety ceiling. Tools whose
        safety class exceeds the ceiling are excluded. Tools that require
        explicit authorization are excluded unless ``authorization_granted``
        is ``True``.

        Raises:
            ToolSelectionError: if no tool passes the gates.

        """
        base_results = self._base.select(criteria)
        selections: list[ToolSelection] = []
        for result in base_results:
            selection = self._enrich(
                result,
                criteria,
                authorization,
                mission_scope,
                authorization_granted,
            )
            if selection is not None:
                selections.append(selection)
        selections.sort(key=lambda item: item.score, reverse=True)
        if not selections:
            raise ToolSelectionError(
                "no tool satisfies criteria within the authorization ceiling"
            )
        return selections[: criteria.limit]

    def select_best(
        self,
        criteria: ToolSelectionCriteria,
        *,
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
        mission_scope: str = "",
        authorization_granted: bool = False,
    ) -> ToolSelection:
        """Return the single best selection or raise :class:`ToolSelectionError`."""
        results = self.select(
            criteria,
            authorization=authorization,
            mission_scope=mission_scope,
            authorization_granted=authorization_granted,
        )
        return results[0]

    def _enrich(
        self,
        result: ToolSelectionResult,
        criteria: ToolSelectionCriteria,
        authorization: ToolSafetyClass,
        mission_scope: str,
        authorization_granted: bool,
    ) -> ToolSelection | None:
        tool_id = result.tool_id
        knowledge = self._registry.get_knowledge(tool_id)
        safety = knowledge.safety_profile if knowledge is not None else None

        if safety is not None and safety.safety_class.exceeds(authorization):
            return None
        if safety is not None and safety.requires_authorization and not authorization_granted:
            return None

        expected_evidence: tuple[str, ...] = ()
        confidence_ceiling = 0.0
        if knowledge is not None:
            mappings = self._registry.evidence_mappings_for(tool_id)
            if mappings:
                expected_evidence = tuple(mapping.evidence_type for mapping in mappings)
            elif knowledge.supported_evidence_types:
                expected_evidence = knowledge.supported_evidence_types

        ceiling = self._registry.get_confidence_ceiling(tool_id)
        confidence_ceiling = (
            ceiling.proof_ceiling
            if ceiling is not None
            else 0.9 if expected_evidence else 0.0
        )

        proof_capabilities = self._registry.proof_capabilities_for(tool_id)
        expected_proof_capability = bool(proof_capabilities)

        risk_level = self._risk_level(safety)
        estimated_cost = self._estimate_cost(knowledge)

        reasoning = list(result.reasons)
        if safety is not None:
            reasoning.append(f"safety class {safety.safety_class.value}")
        if expected_evidence:
            reasoning.append("expected evidence: " + ", ".join(expected_evidence))
        if expected_proof_capability:
            reasoning.append("supports proof execution")

        alternatives = tuple(r.tool_id for r in self._base.select(criteria) if r.tool_id != tool_id)

        return ToolSelection(
            tool_id=tool_id,
            score=result.score,
            reasoning=tuple(reasoning),
            alternatives=alternatives[:3],
            required_inputs=self._required_inputs(knowledge),
            expected_outputs=self._expected_outputs(knowledge),
            risk_level=risk_level,
            estimated_cost=estimated_cost,
            expected_evidence=expected_evidence,
            expected_proof_capability=expected_proof_capability,
            confidence_ceiling=confidence_ceiling,
        )

    @staticmethod
    def _risk_level(safety: ToolSafetyProfile | None) -> str:
        if safety is None:
            return "passive"
        return safety.safety_class.value

    @staticmethod
    def _required_inputs(knowledge) -> tuple[str, ...]:
        if knowledge is None or knowledge.inputs is None:
            return ()
        return tuple(knowledge.inputs.required)

    @staticmethod
    def _expected_outputs(knowledge) -> tuple[str, ...]:
        if knowledge is None or knowledge.outputs is None:
            return ()
        return tuple(knowledge.outputs.event_types)

    @staticmethod
    def _estimate_cost(knowledge) -> float:
        if knowledge is None or knowledge.resource_requirements is None:
            return 0.0
        resources = knowledge.resource_requirements
        cost = resources.cpu_estimate * 0.2 + resources.memory_estimate_mb * 0.001
        return round(cost, 4)


def evidence_strength_for_mapping(mapping: ToolEvidenceMapping) -> EvidenceStrength:
    """Return the evidence strength of an evidence mapping."""
    return mapping.strength


__all__ = [
    "ToolSelector",
    "evidence_strength_for_mapping",
]
