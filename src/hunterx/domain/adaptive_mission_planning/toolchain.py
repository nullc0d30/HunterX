# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool selection, tool chains and failure recovery.

The planner selects tools through the Sprint 025 Tool Mastery port, builds
capability-driven tool chains dynamically (never a hardcoded pipeline) and
recovers from failures by classifying them and choosing retry / retry
differently / replace tool / change strategy / pause / mark unavailable /
replan. Tool substitution is capability-checked, never blind.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionType,
    DependencyKind,
    FailureClass,
    FailureManagement,
)
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    DynamicDependency,
    ToolFallbackRecord,
    ToolSelection,
)


class ToolMasterySelector(Protocol):
    """The Sprint 025 mission-aware selector surface the planner uses."""

    def select(
        self,
        capability: str,
        mission_type: str = "",
        *,
        target_type: str = "",
        limit: int = 4,
    ) -> list[Any]:
        """Return ranked tool selection decisions for ``capability``."""

    def alternatives(self, tool_id: str) -> tuple[str, ...]:
        """Return capability-checked alternative tool ids for ``tool_id``."""


@dataclass(slots=True)
class ToolSelectionEngine:
    """Select tools for action nodes through the mastery selector.

    Args:
        selector: Sprint 025 selector (or adapter exposing ``select``).
        mission_type: mission type string forwarded to the selector.
        default_candidates: fallback tool families per capability when the
            selector yields nothing (deterministic fallback planning).

    """

    selector: Any | None = None
    mission_type: str = "bug-bounty"
    default_candidates: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def select(self, action: ActionNode) -> ToolSelection:
        """Select a tool for ``action`` and bind it onto the node."""
        capability = action.capability
        selection = self._select_capability(capability, target_type=action.asset)
        selection.mission_id = action.mission_id
        selection.action_id = action.action_id
        action.selected_tool = selection.tool_id
        action.tool_candidate_set = (
            (selection.tool_id, *selection.alternatives)
            if selection.tool_id
            else action.tool_candidate_set
        )
        return selection

    def alternatives_for(self, tool_id: str, capability: str = "") -> tuple[str, ...]:
        """Return capability-checked alternatives for ``tool_id``."""
        alternatives: tuple[str, ...] = ()
        selector = self.selector
        if selector is not None:
            try:
                alternatives = tuple(selector.alternatives(tool_id))
            except Exception:  # noqa: BLE001 - degraded selection is a fallback
                alternatives = ()
        if not alternatives:
            alternatives = self.default_candidates.get(capability or "asset_discovery", ())
        return alternatives

    def _select_capability(self, capability: str, *, target_type: str = "") -> ToolSelection:
        selector = self.selector
        decisions: list[Any] = []
        if selector is not None:
            try:
                decisions = list(
                    selector.select(
                        capability,
                        mission_type=self.mission_type,
                        target_type=target_type or "domain",
                        limit=4,
                    )
                )
            except Exception:  # noqa: BLE001 - selection failures degrade gracefully
                decisions = []
        candidates = tuple(decision.tool_id for decision in decisions if getattr(decision, "tool_id", ""))
        if not candidates:
            candidates = self.default_candidates.get(capability, ())
        if not candidates:
            return ToolSelection(
                capability=capability,
                tool_id="",
                alternatives=(),
                score=0.0,
                reasons=("no tool available for capability",),
            )
        reasons = []
        for decision in decisions:
            reason = getattr(decision, "reason", "") or getattr(decision, "explanation", "")
            if reason:
                reasons.append(reason)
        if not reasons:
            reasons.append(f"selected for capability '{capability}'")
        return ToolSelection(
            capability=capability,
            tool_id=candidates[0],
            alternatives=tuple(candidates[1:4]),
            score=round(float(getattr(decisions[0], "score", 0.5)) if decisions else 0.5, 4),
            reasons=tuple(reasons),
            expected_evidence=(f"evidence:{capability}",),
            risk=_default_risk(capability),
            cost=0.3,
        )


def _default_risk(capability: str) -> float:
    active = {
        "sql_injection",
        "xss",
        "ssti",
        "xxe",
        "lfi",
        "rce",
        "idor",
        "ssrf",
    }
    return 0.7 if capability in active else 0.3


class ToolChainPlanner:
    """Build a capability-driven, dependency-aware tool chain.

    The chain is generated from the required capabilities in order; the exact
    chain is not hardcoded — it emerges from the target state and the selected
    tools.
    """

    def plan(self, capabilities: list[str], *, mission_id: str = "") -> list[ActionNode]:
        """Generate ordered actions for ``capabilities``."""
        actions: list[ActionNode] = []
        previous: ActionNode | None = None
        for capability in capabilities:
            node = ActionNode(
                mission_id=mission_id,
                capability=capability,
                action_type=_action_type_for(capability),
                depends_on=(previous.action_id,) if previous else (),
                expected_information_gain=0.7,
                expected_evidence=(f"evidence:{capability}",),
            )
            actions.append(node)
            previous = node
        return actions

    def as_dependencies(self, actions: list[ActionNode]) -> list[DynamicDependency]:
        """Convert the chained actions into typed dependencies."""
        from hunterx.shared.ids import generate_id

        return [
            DynamicDependency(
                dependency_id=generate_id(),
                source_action_id=node.action_id,
                target_action_id=dep_id,
                kind=DependencyKind.DEPENDS_ON,
                rationale="capability chain",
            )
            for node in actions
            for dep_id in node.depends_on
        ]


_ACTION_FOR_CAPABILITY: dict[str, str] = {
    "subdomain_enumeration": "discover_subdomains",
    "dns_enumeration": "enumerate_dns",
    "port_discovery": "identify_services",
    "service_detection": "identify_services",
    "technology_fingerprint": "identify_technology",
    "endpoint_enumeration": "discover_endpoints",
    "content_discovery": "discover_endpoints",
    "parameter_discovery": "discover_parameters",
    "api_mapping": "map_api",
    "graphql_enumeration": "map_graphql",
    "authentication_analysis": "analyze_authentication",
    "authorization_analysis": "test_authorization",
    "vulnerability_scanning": "validate_hypothesis",
    "proof_validation": "collect_proof",
    "replay": "replay_proof",
}


def _action_type_for(capability: str) -> ActionType:
    """Return the canonical action type for ``capability``."""
    return ActionType(_ACTION_FOR_CAPABILITY.get(capability, "investigate_behavior"))


class FailureClassifier:
    """Classify tool failures into canonical :class:`FailureClass` values."""

    def classify(self, error: str = "", *, exit_code: int | None = None, timeout: bool = False) -> FailureClass:
        """Classify an error/exit-code into a canonical failure class."""
        lowered = (error or "").lower()
        if timeout:
            return FailureClass.TIMEOUT
        if exit_code == 429 or "rate limit" in lowered or "rate-limit" in lowered:
            return FailureClass.RATE_LIMIT
        if "timed out" in lowered or "timeout" in lowered:
            return FailureClass.TIMEOUT
        if "connection refused" in lowered or "network" in lowered or "dns resolution" in lowered:
            return FailureClass.NETWORK_ERROR
        if "auth" in lowered or "unauthorized" in lowered or "permission" in lowered:
            return FailureClass.AUTH_ERROR
        if "invalid input" in lowered or "invalid argument" in lowered:
            return FailureClass.INVALID_INPUT
        if "policy" in lowered or "blocked" in lowered or "forbidden" in lowered:
            return FailureClass.POLICY_BLOCK
        if "parse" in lowered or "parser" in lowered:
            return FailureClass.PARSER_ERROR
        if "memory" in lowered or "resource" in lowered or "limit" in lowered:
            return FailureClass.RESOURCE_LIMIT
        if "target" in lowered and "changed" in lowered:
            return FailureClass.TARGET_CHANGED
        return FailureClass.TOOL_ERROR


class RecoveryEngine:
    """Decide the failure-management strategy for a classified failure."""

    def decide(
        self,
        failure_class: FailureClass,
        *,
        retries: int = 0,
        max_retries: int = 2,
        alternatives_available: bool = False,
    ) -> tuple[FailureManagement, str]:
        """Return the management strategy and a reason."""
        if failure_class is FailureClass.RATE_LIMIT:
            return FailureManagement.PAUSE, "rate limited; pause before continuing"
        if failure_class is FailureClass.POLICY_BLOCK:
            return FailureManagement.CHANGE_STRATEGY, "policy block; change strategy"
        if failure_class is FailureClass.AUTH_ERROR:
            return FailureManagement.CHANGE_STRATEGY, "authorization error; change strategy"
        if failure_class is FailureClass.TARGET_CHANGED:
            return FailureManagement.REPLAN, "target changed; replan"
        if failure_class is FailureClass.TIMEOUT and retries < max_retries:
            return FailureManagement.RETRY_DIFFERENTLY, "timeout; retry with different parameters"
        if retries < max_retries:
            return FailureManagement.RETRY, f"retry attempt {retries + 1}"
        if alternatives_available:
            return FailureManagement.REPLACE_TOOL, "tool failed; substitute a capability-equivalent tool"
        if failure_class is FailureClass.RESOURCE_LIMIT:
            return FailureManagement.PAUSE, "resource limit; pause"
        return FailureManagement.MARK_UNAVAILABLE, "tool unavailable; mark unavailable and replan"


class ToolFallbackResolver:
    """Resolve capability-equivalent tool substitutions (never blind)."""

    def resolve(
        self,
        primary_tool: str,
        capability: str,
        selection_engine: ToolSelectionEngine,
        *,
        mission_id: str = "",
        action_id: str = "",
    ) -> ToolFallbackRecord | None:
        """Return a fallback record when a compatible alternative exists."""
        alternatives = selection_engine.alternatives_for(primary_tool, capability)
        for candidate in alternatives:
            if candidate and candidate != primary_tool:
                return ToolFallbackRecord(
                    mission_id=mission_id,
                    action_id=action_id,
                    primary_tool=primary_tool,
                    fallback_tool=candidate,
                    capability=capability,
                    reason=f"capability-equivalent substitution for '{capability}'",
                )
        return None
