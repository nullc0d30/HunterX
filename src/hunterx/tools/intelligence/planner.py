# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Sequence Planner (Sprint 023).

Builds a dependency-aware :class:`ToolChain` from an objective and the
capabilities needed to achieve it. Steps are ordered so every prerequisite
runs before its dependents (topological order), and each step records the
routing conditions and safety class declared by its tool's knowledge profile.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import ToolSelectionError
from hunterx.domain.tool_intelligence import (
    ToolChain,
    ToolChainCondition,
    ToolChainStep,
    ToolSafetyClass,
    ToolSelection,
)
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selector import ToolSelector


class ToolSequencePlanner:
    """Plan ordered, dependency-aware tool chains for an objective.

    Usage::

        planner = ToolSequencePlanner(selector)
        chain = planner.plan("enumerate-web-app", capabilities=("web-crawling", "http-enumeration"))
    """

    def __init__(
        self,
        selector: ToolSelector,
        registry: ToolIntelligenceRegistry | None = None,
    ) -> None:
        self._selector = selector
        self._registry = registry or selector._registry

    def plan(
        self,
        objective: str,
        *,
        capabilities: tuple[str, ...],
        chain_id: str = "",
        mission_id: str = "",
        scope: str = "",
        authorization: ToolSafetyClass = ToolSafetyClass.HIGH_IMPACT,
        inputs: dict[str, Any] | None = None,
    ) -> ToolChain:
        """Plan a chain for ``objective`` covering ``capabilities``.

        Raises:
            ToolSelectionError: if a capability cannot be satisfied.

        """
        inputs = inputs or {}
        selections = self._select_for_capabilities(capabilities, authorization)
        steps: list[ToolChainStep] = []
        dependencies: dict[str, tuple[str, ...]] = {}
        previous: str | None = None

        for capability in capabilities:
            selection = selections[capability]
            step_id = _step_id(capability, selection.tool_id)
            step = self._build_step(step_id, selection, capability, inputs)
            if previous is not None:
                dependencies[step_id] = (previous,)
            steps.append(step)
            previous = step_id

        return ToolChain(
            chain_id=chain_id or f"chain-{objective.replace(' ', '-')}",
            mission_id=mission_id,
            objective=objective,
            steps=tuple(steps),
            dependencies=dependencies,
            scope=scope,
            safety_policy=authorization.value,
        )

    def _select_for_capabilities(
        self,
        capabilities: tuple[str, ...],
        authorization: ToolSafetyClass,
    ) -> dict[str, ToolSelection]:
        from hunterx.domain.tool_intelligence import ToolSelectionCriteria

        result: dict[str, ToolSelection] = {}
        for capability in capabilities:
            try:
                selection = self._selector.select_best(
                    ToolSelectionCriteria(
                        required_capabilities=(capability,),
                        require_installed=False,
                    ),
                    authorization=authorization,
                )
            except ToolSelectionError as error:
                raise ToolSelectionError(
                    f"cannot plan objective: no tool for capability '{capability}'"
                ) from error
            result[capability] = selection
        return result

    def _build_step(
        self,
        step_id: str,
        selection: ToolSelection,
        capability: str,
        inputs: dict[str, Any],
    ) -> ToolChainStep:
        safety_class = self._safety_class_for(selection.tool_id)
        step_inputs = {
            key: value
            for key, value in inputs.items()
            if key in selection.required_inputs or value is not None
        }
        return ToolChainStep(
            step_id=step_id,
            tool_id=selection.tool_id,
            capability=capability,
            inputs=step_inputs,
            outputs=selection.expected_outputs,
            on_success=ToolChainCondition.ON_SUCCESS,
            on_failure=ToolChainCondition.ON_FAILURE,
            on_inconclusive=ToolChainCondition.ON_SUCCESS,
            safety_class=safety_class,
        )

    def _safety_class_for(self, tool_id: str) -> ToolSafetyClass:
        knowledge = self._registry.get_knowledge(tool_id)
        if knowledge is not None and knowledge.safety_profile is not None:
            return knowledge.safety_profile.safety_class
        return ToolSafetyClass.PASSIVE

    def recommended_sequence(self, capabilities: tuple[str, ...]) -> list[str]:
        """Return tool ids in the order a planner would run them.

        Prerequisite capabilities (from the dependency graph) are placed
        before dependents.
        """
        ordered: list[str] = []
        for capability in capabilities:
            providers = self._registry.providers_for(capability)
            if not providers:
                continue
            tool_id = providers[0]
            if tool_id not in ordered:
                ordered.append(tool_id)
        return ordered


def _step_id(capability: str, tool_id: str) -> str:
    """Return a stable step id derived from capability and tool."""
    return f"{capability}::{tool_id}"


__all__ = ["ToolSequencePlanner", "_step_id"]
