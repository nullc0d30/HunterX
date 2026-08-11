# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool AI integration.

Interfaces that let the AI Engine ask intelligence questions about tools:
which tool to use, why, what inputs are required, what outputs are produced,
what comes next, whether a better tool exists, and whether tools should be
combined. The interface is a pure adapter between the AI Engine and the TIP:
it never calls an LLM itself — it shapes structured questions and answers the
AI engine can consume.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from hunterx.domain.exceptions import ToolSelectionError
from hunterx.domain.tool_intelligence import (
    ToolRecommendation,
    ToolSelectionResult,
)
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionEngine


@dataclass(frozen=True, slots=True)
class ToolAIAnswer:
    """A structured answer to an AI-engine tool question.

    Attributes:
        question: the question category (e.g. ``which-tool``).
        tool_ids: tool ids referenced by the answer.
        text: human-readable answer text.
        data: extra structured data for the AI engine.

    """

    question: str
    tool_ids: tuple[str, ...] = ()
    text: str = ""
    data: dict[str, Any] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.data is None:
            object.__setattr__(self, "data", {})


class ToolAIInterface:
    """Answer AI-engine questions about tool selection and behavior.

    Wraps the selection engine and registry to provide grounded answers for
    the standard tool-intelligence questions. Downstream-chain queries are
    injected so the interface stays decoupled from the dependency engine.
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        selection: ToolSelectionEngine,
        *,
        next_tools: Any | None = None,
    ) -> None:
        self._registry = registry
        self._selection = selection
        self._next_tools = next_tools

    def which_tool(
        self,
        capability: str,
        *,
        target_type: str = "",
        inputs: tuple[str, ...] = (),
        mission_profile: str = "",
        require_installed: bool = False,
    ) -> ToolAIAnswer:
        """Ask which tool to use for ``capability``."""
        results = self._select(
            capability=capability,
            target_type=target_type,
            inputs=inputs,
            mission_profile=mission_profile,
            require_installed=require_installed,
        )
        if not results:
            return ToolAIAnswer(
                question="which-tool",
                text=f"No tool found for capability '{capability}'.",
            )
        top = results[0]
        return ToolAIAnswer(
            question="which-tool",
            tool_ids=tuple(r.tool_id for r in results),
            text=f"Use '{top.tool_id}' for '{capability}'.",
            data={"results": [asdict(r) for r in results]},
        )

    def why(self, tool_id: str) -> ToolAIAnswer:
        """Explain why ``tool_id`` would be selected for its capabilities."""
        capabilities = self._registry.capabilities_for(tool_id)
        reasons: list[str] = []
        for capability in capabilities:
            result = self._select(capability=capability, require_installed=False)
            if result and result[0].tool_id == tool_id:
                reasons.append(f"best fit for '{capability}'")
        text = (
            f"'{tool_id}' is recommended because: {', '.join(reasons) or 'it matches the request'}."
        )
        return ToolAIAnswer(question="why", tool_ids=(tool_id,), text=text)

    def required_inputs(self, tool_id: str) -> ToolAIAnswer:
        """Return the inputs ``tool_id`` requires."""
        knowledge = self._registry.get_knowledge(tool_id)
        required = list(knowledge.inputs.required) if knowledge else []
        accepts = list(knowledge.inputs.accepts) if knowledge else []
        return ToolAIAnswer(
            question="required-inputs",
            tool_ids=(tool_id,),
            text=f"'{tool_id}' requires: {', '.join(required) or 'none'}.",
            data={"required": required, "accepts": accepts},
        )

    def expected_outputs(self, tool_id: str) -> ToolAIAnswer:
        """Return the outputs ``tool_id`` produces."""
        knowledge = self._registry.get_knowledge(tool_id)
        formats = list(knowledge.outputs.formats) if knowledge else []
        events = list(knowledge.outputs.event_types) if knowledge else []
        return ToolAIAnswer(
            question="expected-outputs",
            tool_ids=(tool_id,),
            text=f"'{tool_id}' produces: {', '.join(formats) or 'unknown formats'}.",
            data={"formats": formats, "event_types": events},
        )

    def what_next(self, tool_id: str) -> ToolAIAnswer:
        """Ask what should run after ``tool_id`` (dependency-aware)."""
        following: list[str] = []
        if self._next_tools is not None:
            following = list(self._next_tools(tool_id))
        return ToolAIAnswer(
            question="what-next",
            tool_ids=tuple(following),
            text=f"After '{tool_id}', run: {', '.join(following) or 'nothing'}.",
        )

    def better_tool(self, capability: str, current_tool_id: str) -> ToolAIAnswer:
        """Ask whether a better tool than ``current_tool_id`` exists."""
        results = self._select(capability=capability, require_installed=False)
        better = [r for r in results if r.tool_id != current_tool_id]
        if better and better[0].score > 0:
            return ToolAIAnswer(
                question="better-tool",
                tool_ids=(better[0].tool_id,),
                text=f"Consider '{better[0].tool_id}' instead of '{current_tool_id}'.",
            )
        return ToolAIAnswer(
            question="better-tool",
            tool_ids=(current_tool_id,),
            text=f"'{current_tool_id}' is already the best fit.",
        )

    def combine(self, capability: str, results: list[ToolSelectionResult]) -> ToolAIAnswer:
        """Advise whether multiple tools should be combined for ``capability``."""
        if len(results) > 1:
            names = [r.tool_id for r in results]
            return ToolAIAnswer(
                question="combine",
                tool_ids=tuple(names),
                text=f"Combine {', '.join(names)} for broader coverage.",
            )
        if results:
            return ToolAIAnswer(
                question="combine",
                tool_ids=(results[0].tool_id,),
                text=f"A single tool ('{results[0].tool_id}') is sufficient.",
            )
        return ToolAIAnswer(question="combine", text="No tools available to combine.")

    def _select(
        self,
        *,
        capability: str,
        target_type: str = "",
        inputs: tuple[str, ...] = (),
        mission_profile: str = "",
        require_installed: bool = False,
    ) -> list[ToolSelectionResult]:
        from hunterx.domain.tool_intelligence import ToolSelectionCriteria

        try:
            return self._selection.select(
                ToolSelectionCriteria(
                    required_capabilities=(capability,),
                    target_type=target_type,
                    available_inputs=inputs,
                    mission_profile=mission_profile,
                    require_installed=require_installed,
                    limit=5,
                )
            )
        except ToolSelectionError:
            return []


def build_recommendation_prompt(capability: str, recommendations: list[ToolRecommendation]) -> str:
    """Build a prompt describing recommendations for an AI engine."""
    lines = [f"Recommendations for capability '{capability}':"]
    for recommendation in recommendations:
        lines.append(
            f"- {recommendation.kind.value}: {recommendation.tool_id} "
            f"(score {recommendation.score:.2f})"
        )
        if recommendation.reason:
            lines.append(f"  reason: {recommendation.reason}")
    return "\n".join(lines)
