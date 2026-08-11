# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission replanning.

The mission may replan when new assets, technologies, endpoints, cloud
providers or vulnerability intelligence are discovered, when a validation
result changes priority, or when a tool failure changes capability
availability. Replanning NEVER expands scope automatically: newly discovered
assets are classified and only in-scope assets continue automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunterx.domain.orchestration.enums import ScopeClassification
from hunterx.engines.orchestration.scope import MissionScopeGuard


@dataclass(frozen=True, slots=True)
class DiscoveredAsset:
    """A newly discovered asset awaiting classification.

    Attributes:
        identifier: the discovered asset identifier.
        kind: asset kind (``hostname``, ``ip``, ``cidr``, ``url``, ``cloud``).
        source: the tool/step that discovered it.

    """

    identifier: str
    kind: str = "hostname"
    source: str = ""


@dataclass(slots=True)
class ReplanRequest:
    """A replanning request.

    Attributes:
        mission_id: owning mission.
        plan_id: current plan.
        reason: replanning rationale.
        discovered_assets: newly discovered assets to classify.
        new_technologies: newly discovered technologies.
        new_endpoints: newly discovered endpoint kinds.
        new_providers: newly discovered cloud providers.
        capability_changes: tool capability availability changes.

    """

    mission_id: str = ""
    plan_id: str = ""
    reason: str = ""
    discovered_assets: list[DiscoveredAsset] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    new_providers: list[str] = field(default_factory=list)
    capability_changes: dict[str, bool] = field(default_factory=dict)


@dataclass(slots=True)
class ReplanDecision:
    """The outcome of evaluating a replanning request.

    Attributes:
        replan_needed: whether a new plan should be generated.
        reason: the reason to replan (or why not).
        classifications: per-asset scope classifications.
        in_scope_assets: assets classified IN_SCOPE.
        blocked_assets: assets not in scope (never acted upon).
        triggered_capabilities: capabilities that should be added.

    """

    replan_needed: bool = False
    reason: str = ""
    classifications: dict[str, str] = field(default_factory=dict)
    in_scope_assets: list[str] = field(default_factory=list)
    blocked_assets: list[str] = field(default_factory=list)
    triggered_capabilities: list[str] = field(default_factory=list)


class ReplanningEngine:
    """Evaluates replanning requests and classifies discovered assets.

    The engine never expands scope: assets classified ``OUT_OF_SCOPE`` or
    ``REQUIRES_AUTHORIZATION`` are blocked and recorded. Only in-scope assets
    may continue automatically.
    """

    def __init__(self, guard: MissionScopeGuard | None = None) -> None:
        self._guard = guard

    def evaluate(self, request: ReplanRequest) -> ReplanDecision:
        """Evaluate a replanning request.

        Args:
            request: the replanning request to evaluate.

        """
        guard = self._guard or MissionScopeGuard()
        classifications: dict[str, str] = {}
        in_scope: list[str] = []
        blocked: list[str] = []

        for asset in request.discovered_assets:
            decision = guard.decides(asset.identifier)
            classifications[asset.identifier] = decision.classification.value
            if decision.classification is ScopeClassification.IN_SCOPE:
                in_scope.append(asset.identifier)
            else:
                blocked.append(asset.identifier)

        triggered = list(request.new_endpoints)
        for technology in request.new_technologies:
            triggered.append(f"technology:{technology}")
        for provider in request.new_providers:
            triggered.append(f"cloud:{provider}")

        replan_needed = bool(in_scope or request.new_technologies or request.new_endpoints or request.new_providers)
        reason_parts: list[str] = []
        if in_scope:
            reason_parts.append(f"{len(in_scope)} new in-scope asset(s)")
        if request.new_technologies:
            reason_parts.append(f"{len(request.new_technologies)} new technology(ies)")
        if request.new_endpoints:
            reason_parts.append(f"{len(request.new_endpoints)} new endpoint kind(s)")
        if request.new_providers:
            reason_parts.append(f"{len(request.new_providers)} new cloud provider(s)")

        return ReplanDecision(
            replan_needed=replan_needed,
            reason="; ".join(reason_parts) if reason_parts else request.reason or "no replan needed",
            classifications=classifications,
            in_scope_assets=in_scope,
            blocked_assets=blocked,
            triggered_capabilities=triggered,
        )
