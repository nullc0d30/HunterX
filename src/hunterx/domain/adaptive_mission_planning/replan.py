# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Replanning engine.

Decides whether new intelligence invalidates part of the current plan and, if
so, produces a :class:`PlanDelta` (never a full-plan rebuild). Every revision
is versioned and replayable through :class:`PlanVersion`.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    ActionType,
    BranchKind,
    PlanDeltaKind,
    ReplanTrigger,
    ValidationLevel,
)
from hunterx.domain.adaptive_mission_planning.graph import AdaptiveExecutionGraph
from hunterx.domain.adaptive_mission_planning.models import (
    ActionNode,
    ConditionalBranch,
    PlanDelta,
    PlanDeltaChange,
    PlanVersion,
)


class ReplanSignal:
    """A detected condition that may require replanning.

    Attributes:
        trigger: the canonical :class:`ReplanTrigger`.
        asset_key: affected asset (may be empty).
        detail: structured detail map.
        priority: how strongly the signal should drive a replan.

    """

    def __init__(self, trigger: ReplanTrigger, *, asset_key: str = "", detail: dict[str, Any] | None = None, priority: float = 0.5) -> None:
        self.trigger = trigger
        self.asset_key = asset_key
        self.detail = detail or {}
        self.priority = priority


class ReplanningEngine:
    """Evaluate replanning signals and emit :class:`PlanDelta` results.

    Args:
        min_signal_priority: signals below this priority are ignored.

    """

    def __init__(self, *, min_signal_priority: float = 0.3) -> None:
        self.min_signal_priority = min_signal_priority

    def evaluate(self, signals: list[ReplanSignal]) -> ReplanSignal | None:
        """Return the strongest actionable signal or ``None``."""
        actionable = [signal for signal in signals if signal.priority >= self.min_signal_priority]
        if not actionable:
            return None
        return max(actionable, key=lambda signal: signal.priority)

    def build_delta(
        self,
        *,
        mission_id: str,
        graph: AdaptiveExecutionGraph,
        signal: ReplanSignal,
        current_version: int,
        reason: str,
        created_by: str = "replanning_engine",
    ) -> PlanDelta:
        """Build a :class:`PlanDelta` responding to ``signal``.

        The delta only mutates what the signal requires; the rest of the plan
        is untouched. The produced version is ``current_version + 1``.
        """
        changes: list[PlanDeltaChange] = []
        if signal.trigger is ReplanTrigger.NEW_ASSET_DISCOVERED:
            changes = self._on_new_asset(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.NEW_TECHNOLOGY_DISCOVERED:
            changes = self._on_new_technology(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.NEW_ENDPOINT_DISCOVERED:
            changes = self._on_new_endpoint(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.JAVASCRIPT_ANALYSIS:
            changes = self._on_javascript_analysis(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.CAPABILITY_SCHEDULED:
            changes = self._on_capability(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.NEW_HYPOTHESIS_CREATED:
            changes = self._on_new_hypothesis(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.CONFLICTING_EVIDENCE:
            changes = self._on_conflict(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.PROOF_FAILED:
            changes = self._on_proof_failed(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.SCOPE_CHANGED:
            changes = self._on_scope_changed(graph, signal, mission_id)
        elif signal.trigger is ReplanTrigger.UNKNOWN_BEHAVIOR_OBSERVED:
            changes = self._on_unknown_behavior(graph, signal, mission_id)
        elif signal.trigger in (
            ReplanTrigger.NEW_PARAMETER_DISCOVERED,
            ReplanTrigger.HYPOTHESIS_CONFIDENCE_CHANGED,
            ReplanTrigger.PROOF_BECOMES_POSSIBLE,
            ReplanTrigger.TARGET_STATE_CHANGED,
            ReplanTrigger.TOOL_CAPABILITY_CHANGED,
            ReplanTrigger.RISK_THRESHOLD_CHANGED,
            ReplanTrigger.MISSION_OBJECTIVE_CHANGED,
            ReplanTrigger.CRITICAL_INFORMATION_GAP,
        ):
            changes = self._on_generic_signal(graph, signal, mission_id)

        changes = self._filter_replays(changes, graph)

        return PlanDelta(
            mission_id=mission_id,
            plan_version=current_version + 1,
            parent_version=current_version,
            changes=tuple(changes),
            trigger=signal.trigger,
            reason=reason,
            decision_provenance={
                "created_by": created_by,
                "asset_key": signal.asset_key,
                "detail": signal.detail,
                "priority": signal.priority,
            },
        )

    def _filter_replays(self, changes: list[PlanDeltaChange], graph: AdaptiveExecutionGraph) -> list[PlanDeltaChange]:
        """Drop ADD_ACTION changes that replay a materially identical action.

        Replay protection lives in the planning domain so it applies to every
        replanning trigger, not just one caller: an action that shares the
        identity (capability, asset, hypothesis, parameter/technology context,
        tool) of an existing graph action — terminal or not — must not be
        scheduled again. Only genuinely new state (a new endpoint, parameter,
        technology, asset or hypothesis) produces a new identity and is
        permitted.
        """
        deduplicated: list[PlanDeltaChange] = []
        for change in changes:
            if (
                change.kind is PlanDeltaKind.ADD_ACTION
                and change.node is not None
                and graph.has_identical_action(change.node)
            ):
                # The repeated branch carries no new state: it is not added.
                continue
            deduplicated.append(change)
        return deduplicated

    def version_for(self, delta: PlanDelta, *, created_by: str = "planner") -> PlanVersion:
        """Build the :class:`PlanVersion` describing ``delta``."""
        return PlanVersion(
            plan_version=delta.plan_version,
            parent_version=delta.parent_version,
            reason=delta.reason,
            trigger=delta.trigger,
            changed_nodes=tuple(
                change.action_id for change in delta.changes if change.action_id
            ),
            changed_dependencies=tuple(
                change.dependency.dependency_id
                for change in delta.changes
                if change.dependency is not None
            ),
            created_by=created_by,
            decision_provenance=delta.decision_provenance,
        )

    # -- signal handlers ----------------------------------------------------

    def _on_new_asset(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "new-asset"
        discover = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.IDENTIFY_SERVICES,
            asset=asset,
            capability="port_discovery",
            expected_information_gain=0.8,
            expected_evidence=(f"evidence:port_discovery:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=discover.action_id,
                node=discover,
                reason=f"new asset '{asset}' discovered; schedule service discovery",
            )
        ]

    def _on_new_technology(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.VALIDATE_HYPOTHESIS,
            asset=asset,
            capability="vulnerability_scanning",
            expected_information_gain=0.7,
            expected_evidence=(f"evidence:vulnerability_scanning:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value, "technology": signal.detail.get("technology", "")},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason="new technology observed; schedule vulnerability-model analysis",
            )
        ]

    def _on_new_endpoint(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        params = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.DISCOVER_PARAMETERS,
            asset=asset,
            capability="parameter_discovery",
            expected_information_gain=0.7,
            expected_evidence=(f"evidence:parameter_discovery:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=params.action_id,
                node=params,
                reason="new endpoint discovered; schedule parameter discovery",
            )
        ]

    def _on_javascript_analysis(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.DISCOVER_PARAMETERS,
            asset=asset,
            capability="javascript_analysis",
            expected_information_gain=0.7,
            expected_evidence=(f"evidence:javascript_analysis:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason="script asset discovered; schedule javascript analysis",
            )
        ]

    def _on_capability(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        """Schedule an explicit capability on an asset (deterministic planner).

        Used by the adaptive runner's deterministic planner to extend the plan
        with a concrete capability (e.g. ``content_discovery``, ``api_mapping``)
        without inventing a trigger name. The action type is derived from the
        capability; replay protection still applies through
        :meth:`_filter_replays`.
        """
        asset = signal.asset_key or "asset"
        capability = str(signal.detail.get("capability") or "").strip() or "vulnerability_scanning"
        action_type = _action_type_for_capability(capability)
        node = ActionNode(
            mission_id=mission_id,
            action_type=action_type,
            asset=asset,
            capability=capability,
            expected_information_gain=0.7,
            expected_evidence=(f"evidence:{capability}:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value, "capability": capability},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason=f"deterministic planner scheduled capability '{capability}'",
            )
        ]

    def _on_new_hypothesis(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        hypothesis_id = signal.detail.get("hypothesis_id", "")
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.VALIDATE_HYPOTHESIS,
            asset=asset,
            capability=signal.detail.get("capability", "vulnerability_scanning"),
            hypothesis_id=hypothesis_id,
            expected_information_gain=0.8,
            expected_evidence=(f"evidence:validation:{hypothesis_id}",),
            validation_level=ValidationLevel.VALIDATION,
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value, "hypothesis_id": hypothesis_id},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason=f"new hypothesis '{hypothesis_id}' created; schedule validation",
            )
        ]

    def _on_conflict(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.RESOLVE_CONFLICT,
            asset=asset,
            capability="asset_discovery",
            expected_information_gain=0.9,
            expected_evidence=(f"evidence:conflict_resolution:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value, "conflict": signal.detail.get("conflict_id", "")},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason="conflicting evidence observed; create investigation branch to re-test current state",
            ),
            PlanDeltaChange(
                kind=PlanDeltaKind.CREATE_BRANCH,
                branch=ConditionalBranch(
                    branch_id=f"branch-conflict-{node.action_id}",
                    kind=BranchKind.FORK,
                    condition="evidence_conflict",
                    then_action_ids=(node.action_id,),
                    rationale="re-test to resolve conflicting observations",
                ),
                reason=f"investigation branch for conflict on '{asset}'",
            ),
        ]

    def _on_proof_failed(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        hypothesis_id = signal.detail.get("hypothesis_id", "")
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.INVESTIGATE_BEHAVIOR,
            asset=asset,
            capability="vulnerability_scanning",
            hypothesis_id=hypothesis_id,
            expected_information_gain=0.6,
            expected_evidence=(f"evidence:proof_failure:{hypothesis_id or asset}",),
            validation_level=ValidationLevel.VALIDATION,
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason="proof failed; revalidate the hypothesis under the evidence contract",
            )
        ]

    def _on_scope_changed(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        changes: list[PlanDeltaChange] = []
        excluded = set(signal.detail.get("excluded_assets", []) or [])
        for action in graph.actions.values():
            if action.asset and action.asset in excluded and not action.status.is_terminal:
                action.mark(ActionStatus.BLOCKED)
                changes.append(
                    PlanDeltaChange(
                        kind=PlanDeltaKind.REMOVE_ACTION,
                        action_id=action.action_id,
                        reason=f"asset '{action.asset}' removed from scope",
                    )
                )
        return changes

    def _on_unknown_behavior(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        asset = signal.asset_key or "asset"
        node = ActionNode(
            mission_id=mission_id,
            action_type=ActionType.INVESTIGATE_BEHAVIOR,
            asset=asset,
            capability="asset_discovery",
            expected_information_gain=0.9,
            expected_evidence=(f"evidence:behavior:{asset}",),
            status=ActionStatus.PROPOSED,
            provenance={"source": "replan", "trigger": signal.trigger.value},
        )
        return [
            PlanDeltaChange(
                kind=PlanDeltaKind.ADD_ACTION,
                action_id=node.action_id,
                node=node,
                reason="unknown behavior observed; create investigation branch (characterize → hypothesize → experiment)",
            ),
            PlanDeltaChange(
                kind=PlanDeltaKind.CREATE_BRANCH,
                branch=ConditionalBranch(
                    branch_id=f"branch-behavior-{node.action_id}",
                    kind=BranchKind.FORK,
                    condition="unknown_behavior",
                    then_action_ids=(node.action_id,),
                    rationale="investigate unknown behavior without requiring a known signature",
                ),
                reason=f"investigation branch for unknown behavior on '{asset}'",
            ),
        ]

    def _on_generic_signal(self, graph: AdaptiveExecutionGraph, signal: ReplanSignal, mission_id: str) -> list[PlanDeltaChange]:
        return []


#: Capability → canonical action type used by the deterministic planner when it
#: schedules a capability explicitly (``CAPABILITY_SCHEDULED``).
_ACTION_TYPE_BY_CAPABILITY: dict[str, ActionType] = {
    "asset_discovery": ActionType.DISCOVER_SUBDOMAINS,
    "subdomain_enumeration": ActionType.DISCOVER_SUBDOMAINS,
    "dns_enumeration": ActionType.ENUMERATE_DNS,
    "port_discovery": ActionType.IDENTIFY_SERVICES,
    "service_detection": ActionType.IDENTIFY_SERVICES,
    "technology_fingerprint": ActionType.IDENTIFY_TECHNOLOGY,
    "certificate_enumeration": ActionType.ENUMERATE_DNS,
    "endpoint_enumeration": ActionType.DISCOVER_ENDPOINTS,
    "content_discovery": ActionType.DISCOVER_ENDPOINTS,
    "javascript_analysis": ActionType.DISCOVER_ENDPOINTS,
    "parameter_discovery": ActionType.DISCOVER_PARAMETERS,
    "api_mapping": ActionType.MAP_API,
    "authentication_analysis": ActionType.ANALYZE_AUTHENTICATION,
    "authorization_analysis": ActionType.TEST_AUTHORIZATION,
    "vulnerability_scanning": ActionType.VALIDATE_HYPOTHESIS,
    "proof_validation": ActionType.COLLECT_PROOF,
    "replay": ActionType.REPLAY_PROOF,
    "secret_detection": ActionType.INVESTIGATE_BEHAVIOR,
    "dependency_check": ActionType.GENERATE_HYPOTHESIS,
}


def _action_type_for_capability(capability: str) -> ActionType:
    """Return the canonical :class:`ActionType` for ``capability``."""
    return _ACTION_TYPE_BY_CAPABILITY.get(capability, ActionType.INVESTIGATE_BEHAVIOR)
