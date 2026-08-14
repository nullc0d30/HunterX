# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous mission execution runner.

Sprint 033. Bridges the adaptive mission orchestrator (decide → ingest →
replan) and the Tool Integration SDK so a real assessment actually executes:

    decision → action → tool execution → observation → adaptive replanning

The runner is an application-layer use case. It never hardcodes a tool chain:
every cycle asks the mission decision engine to rank the ready actions of the
adaptive plan, executes the selected tool through the Tool Integration SDK,
ingests the result into the mission aggregate and lets the planner reconsider
the plan from the new observations (Observe → Hypothesize → Probe → Verify).

Execution failures are never silent: a failed tool execution produces a
persisted observation, negative-evidence record, a classified planning failure
and an explicit cycle outcome instead of returning the initial mission
snapshot.
"""

from __future__ import annotations

import contextlib
from typing import Any

from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.execution import ExecutionStatus
from hunterx.domain.target_intelligence.enums import CoverageState
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine

#: Canonical observation types per discovery capability. These drive both the
#: persisted observation and the target-model context updates.
_OBSERVATION_TYPE: dict[str, str] = {
    "asset_discovery": "asset",
    "subdomain_enumeration": "asset",
    "dns_enumeration": "dns_record",
    "port_discovery": "port",
    "service_detection": "service",
    "technology_fingerprint": "technology",
    "certificate_enumeration": "dns_record",
    "endpoint_enumeration": "endpoint",
    "content_discovery": "endpoint",
    "parameter_discovery": "parameter",
    "api_mapping": "api",
    "authentication_analysis": "auth",
    "authorization_analysis": "authorization",
    "vulnerability_scanning": "vulnerability",
    "sql_injection": "vulnerability",
    "xss": "vulnerability",
    "ssrf": "vulnerability",
    "ssti": "vulnerability",
    "xxe": "vulnerability",
    "lfi": "vulnerability",
    "rce": "vulnerability",
    "idor": "vulnerability",
    "api_security": "vulnerability",
    "graphql_security": "vulnerability",
    "secret_detection": "vulnerability",
    "dependency_check": "vulnerability",
    "cloud_ownership_mapping": "api",
    "proof_validation": "proof",
    "replay": "proof",
}

#: Replanning signals a successful observation may raise.
_TRIGGER_BY_OBSERVATION: dict[str, ReplanTrigger] = {
    "asset": ReplanTrigger.NEW_ASSET_DISCOVERED,
    "subdomain": ReplanTrigger.NEW_ASSET_DISCOVERED,
    "host": ReplanTrigger.NEW_ASSET_DISCOVERED,
    "domain": ReplanTrigger.NEW_ASSET_DISCOVERED,
    "technology": ReplanTrigger.NEW_TECHNOLOGY_DISCOVERED,
    "endpoint": ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
    "url": ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
    "api": ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
    "parameter": ReplanTrigger.NEW_PARAMETER_DISCOVERED,
    "vulnerability": ReplanTrigger.NEW_HYPOTHESIS_CREATED,
}

#: Capability a replan signal schedules (deduplicated against the live graph).
_CAPABILITY_BY_TRIGGER: dict[ReplanTrigger, str] = {
    ReplanTrigger.NEW_ASSET_DISCOVERED: "port_discovery",
    ReplanTrigger.NEW_TECHNOLOGY_DISCOVERED: "vulnerability_scanning",
    ReplanTrigger.NEW_ENDPOINT_DISCOVERED: "parameter_discovery",
    ReplanTrigger.NEW_PARAMETER_DISCOVERED: "vulnerability_scanning",
    ReplanTrigger.NEW_HYPOTHESIS_CREATED: "vulnerability_scanning",
}


class MissionExecutionService:
    """Drive one or many adaptive mission execution cycles.

    Args:
        orchestration: the mission orchestration application service (owns the
            mission aggregate, persistence and events).
        planning: the Sprint 027 adaptive planning engine (owns the execution
            graph, tool selection and replanning).
        execution_engine: the Tool Integration SDK execution engine.
        event_bus: optional messaging port for runner-level events.

    """

    def __init__(
        self,
        *,
        orchestration: MissionOrchestrationService,
        planning: AdaptiveMissionPlanningEngine,
        execution_engine: ExecutionEngine | None = None,
        event_bus: Any | None = None,
        readiness: Any | None = None,
    ) -> None:
        self._orchestration = orchestration
        self._planning = planning
        self._engine = execution_engine
        self._event_bus = event_bus
        self._readiness = readiness

    # -- public API ---------------------------------------------------------

    def execute_cycle(self, mission_id: str, *, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one Observe → Decide → Act → Observe cycle for ``mission_id``.

        Returns a JSON-safe cycle outcome describing the decision, the tool
        execution attempt and its outcome. Never marks a running mission as
        complete just because a single cycle finished.
        """
        mission = self._orchestration.get(mission_id)
        if mission.mission.state.is_terminal:
            return self._cycle_outcome(mission_id, status="skipped", reason="mission terminal")
        self._approve_ready_actions(mission_id)
        decision = self._orchestration.decide_next(mission_id)
        if decision is None:
            if self._advance_state(mission_id):
                return self._cycle_outcome(
                    mission_id,
                    status="reassessed",
                    reason="no ready action; mission advanced to reassessment",
                )
            return self._cycle_outcome(mission_id, status="idle", reason="no ready action")
        return self._execute_decision(mission_id, decision, parameters=parameters)

    def run(
        self,
        mission_id: str,
        *,
        max_cycles: int = 16,
        max_idle_cycles: int = 3,
        parameters: dict[str, Any] | None = None,
        auto_provision: bool = True,
    ) -> dict[str, Any]:
        """Run the adaptive mission execution loop until it settles.

        The loop stops when the mission reaches a terminal state, the execution
        budget is exhausted, no actionable decision remains, or ``max_cycles``
        is reached. The mission is never marked completed merely because the
        initial discovery plan has been walked.

        When a tool-readiness service is wired, a mission preflight runs first:
        required capabilities without an available provider (and whose
        provisioning fails) return a structured ``blocked`` outcome and the
        mission never enters active execution. Missing optional capabilities
        degrade the outcome but do not stop the loop.
        """
        preflight = self._preflight(mission_id, auto_provision=auto_provision)
        if preflight is not None and not preflight.may_execute:
            return {
                "mission_id": mission_id,
                "cycles_run": 0,
                "cycles": [],
                "planning_state": self._orchestration.get(mission_id).mission.state.value,
                "status": "blocked",
                "reason": preflight.blocked_reason,
                "preflight": preflight.to_dict(),
                "executions_used": 0,
                "observations": 0,
                "decisions": 0,
                "tool_executions": 0,
                "coverage_ratio": 0.0,
            }
        cycles: list[dict[str, Any]] = []
        idle = 0
        self._seed_coverage(mission_id)
        for _ in range(1, max_cycles + 1):
            mission = self._orchestration.get(mission_id)
            if mission.mission.state.is_terminal:
                break
            if mission.budget.executions_budget and mission.budget.executions_used >= mission.budget.executions_budget:
                break
            cycle = self.execute_cycle(mission_id, parameters=parameters)
            cycles.append(cycle)
            if cycle.get("status") in ("idle", "skipped"):
                idle += 1
                if idle >= max_idle_cycles:
                    break
                continue
            idle = 0
            stop = self._orchestration.stop_condition(mission_id)
            if stop and stop.get("stop_condition"):
                break
        self._record_telemetry(mission_id)
        mission = self._orchestration.get(mission_id)
        return {
            "mission_id": mission_id,
            "cycles_run": len(cycles),
            "cycles": cycles,
            "planning_state": mission.mission.state.value,
            "status": "degraded" if preflight is not None and preflight.status.value == "degraded" else "completed",
            "preflight": preflight.to_dict() if preflight is not None else None,
            "executions_used": mission.budget.executions_used,
            "observations": len(mission.observations),
            "decisions": len(mission.decisions),
            "tool_executions": len(mission.context.tool_executions),
            "coverage_ratio": mission.coverage_ratio(),
        }

    # -- decision / execution -----------------------------------------------

    def _preflight(self, mission_id: str, *, auto_provision: bool = True) -> Any | None:
        """Run the tool-readiness preflight gate for the mission plan.

        Returns ``None`` when no readiness service is wired (legacy path — the
        runner proceeds unconditionally). Otherwise returns the preflight
        verdict; a blocked verdict prevents active execution.
        """
        readiness = self._readiness
        if readiness is None:
            return None
        capabilities: list[str] = []
        try:
            graph = self._planning.get_plan(mission_id)
            capabilities = [action.capability for action in graph.actions.values()]
        except Exception:  # noqa: BLE001 - preflight degrades to pass on plan errors
            pass
        if not capabilities:
            return None
        try:
            return readiness.preflight(
                capabilities,
                mission_id=mission_id,
                auto_provision=auto_provision,
            )
        except Exception:  # noqa: BLE001 - preflight must never crash the runner
            return None

    def _approve_ready_actions(self, mission_id: str) -> None:
        """Approve and bind tools on actions that are ready to run.

        Replanned actions enter the graph as ``PROPOSED``; the orchestrator
        promotes them to ``APPROVED`` the moment their dependencies are
        terminal so the decision engine can rank them. Tools are bound through
        the planning engine's capability-aware selector.
        """
        graph = self._planning.get_plan(mission_id)
        for action in graph.ready_actions(approved_only=False):
            if action.status is ActionStatus.PROPOSED:
                action.mark(ActionStatus.APPROVED)
            if not action.selected_tool:
                with contextlib.suppress(Exception):  # degraded selection is handled downstream
                    self._planning.select_tool(mission_id, action.action_id)

    def _execute_decision(
        self,
        mission_id: str,
        decision: dict[str, Any],
        *,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        action_id = str(decision.get("next_action", ""))
        tool_id = str(decision.get("tool_id", ""))
        capability = str(decision.get("capability", ""))
        mission = self._orchestration.get(mission_id)
        target = mission.context.target_id
        action = self._planning.get_action(mission_id, action_id)
        action.mark(ActionStatus.RUNNING)

        if not tool_id:
            return self._fail_execution(
                mission_id,
                action_id=action_id,
                capability=capability,
                tool_id="",
                error="no tool available for capability",
            )

        engine = self._engine
        if engine is None:
            return self._fail_execution(
                mission_id,
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                error="no execution engine wired",
            )

        try:
            pipeline = engine.execute(self._build_context(mission_id, tool_id, target, parameters))
        except Exception as exc:  # noqa: BLE001 - surfaced as a structured failure
            return self._fail_execution(
                mission_id,
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                error=str(exc),
            )
        return self._handle_execution(mission_id, action_id, capability, tool_id, target, pipeline)

    def _handle_execution(
        self,
        mission_id: str,
        action_id: str,
        capability: str,
        tool_id: str,
        target: str,
        pipeline: Any,
    ) -> dict[str, Any]:
        result = pipeline.result
        if result.ok:
            raw = self._observation_from_result(capability, result)
            self._orchestration.ingest_result(
                mission_id,
                tool_id=tool_id,
                action_id=action_id,
                asset_key=target,
                raw=raw,
            )
            self._planning.get_action(mission_id, action_id).mark(ActionStatus.COMPLETED)
            self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
            self._replan_from_observation(mission_id, capability, raw)
            return self._cycle_outcome(
                mission_id,
                status="completed",
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                observation_type=raw.get("observation_type", ""),
            )
        return self._fail_execution(
            mission_id,
            action_id=action_id,
            capability=capability,
            tool_id=tool_id,
            error=result.error or "tool execution failed",
            failure_kind=result.failure_kind.value if result.failure_kind else "",
            status_value=result.status.value,
            exit_code=result.output.exit_code,
        )

    def _fail_execution(
        self,
        mission_id: str,
        *,
        action_id: str,
        capability: str,
        tool_id: str,
        error: str,
        failure_kind: str = "",
        status_value: str = "",
        exit_code: int = 0,
    ) -> dict[str, Any]:
        """Record a structured tool failure and keep the mission active.

        A failure is a real, observable event: a persisted failure observation,
        classified planning failure, negative-evidence record and coverage cell
        — never a silent return to the initial snapshot.
        """
        mission = self._orchestration.get(mission_id)
        target = mission.context.target_id
        self._orchestration.ingest_result(
            mission_id,
            tool_id=tool_id or "",
            action_id=action_id,
            asset_key=target,
            raw={
                "observation_type": "tool_failure",
                "content": {
                    "error": error[:2000],
                    "failure_kind": failure_kind,
                    "status": status_value,
                    "exit_code": exit_code,
                },
                "confidence": 0.0,
            },
        )
        with contextlib.suppress(Exception):  # failure classification is best-effort
            self._planning.record_failure(
                mission_id,
                action_id,
                tool_id=tool_id,
                error=error,
                timeout=status_value == ExecutionStatus.TIMED_OUT.value,
                exit_code=exit_code,
            )
        with contextlib.suppress(Exception):  # action may already be terminal
            self._planning.get_action(mission_id, action_id).mark(ActionStatus.FAILED)
        self._orchestration.record_negative(
            mission_id,
            asset_key=target,
            capability=capability,
            kind="blocked",
            tool_id=tool_id,
            outcome="tool failure",
            notes=error[:500],
        )
        self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
        return self._cycle_outcome(
            mission_id,
            status="failed",
            action_id=action_id,
            capability=capability,
            tool_id=tool_id,
            error=error,
            failure_kind=failure_kind,
        )

    # -- helpers --------------------------------------------------------------

    def _build_context(
        self,
        mission_id: str,
        tool_id: str,
        target: str,
        parameters: dict[str, Any] | None,
    ) -> Any:
        builder = (
            ExecutionContextBuilder(tool_id=tool_id, target=target)
            .with_mission(mission_id)
            .with_parameters(dict(parameters or {}))
        )
        return builder.build()

    def _observation_from_result(self, capability: str, result: Any) -> dict[str, Any]:
        """Project a tool execution result into a normalized observation dict.

        The raw tool output is treated as data — never as instructions. The
        observation type is derived from the action's capability.
        """
        output = result.output
        content: dict[str, Any] = {}
        if output.json is not None:
            content = output.json if isinstance(output.json, dict) else {"value": output.json}
        elif output.stdout:
            content = {"stdout": output.stdout[:20000]}
        return {
            "observation_type": _OBSERVATION_TYPE.get(capability, "asset"),
            "content": content,
            "confidence": 0.7 if content else 0.0,
        }

    def _seed_coverage(self, mission_id: str) -> None:
        """Seed the coverage matrix from the plan's capabilities.

        Without a denominator the coverage ratio would jump to 1.0 after a
        single tested cell (and falsely trigger ``coverage_target_achieved``).
        Seeding every planned capability as ``NOT_ASSESSED`` gives the ratio a
        real basis: it only approaches the target as the plan is exercised.
        """
        mission = self._orchestration.get(mission_id)
        if mission.coverage:
            return
        target = mission.context.target_id or "target"
        graph = self._planning.get_plan(mission_id)
        for action in graph.actions.values():
            self._record_coverage(mission_id, target, action.capability, "", state=CoverageState.NOT_ASSESSED)

    def _record_coverage(
        self,
        mission_id: str,
        asset_key: str,
        capability: str,
        tool_id: str,
        *,
        state: CoverageState,
    ) -> None:
        with contextlib.suppress(Exception):  # coverage is best-effort telemetry
            self._orchestration.record_coverage(
                mission_id,
                asset_key=asset_key or "target",
                capability=capability,
                state=state,
                tool_id=tool_id,
                confidence=0.7 if state is CoverageState.TESTED else 0.0,
            )

    def _replan_from_observation(self, mission_id: str, capability: str, raw: dict[str, Any]) -> None:
        """Let the planner reconsider the mission from the new observation.

        Replanning is deduplicated: a capability already present in the live
        graph (non-terminal) is never scheduled twice.
        """
        trigger = _TRIGGER_BY_OBSERVATION.get(str(raw.get("observation_type", "")))
        if trigger is None:
            return
        content = raw.get("content")
        if not content:
            return
        new_capability = _CAPABILITY_BY_TRIGGER.get(trigger, "")
        if new_capability:
            # Never schedule the same capability twice, regardless of status:
            # re-planning must extend the plan, not loop over the same action.
            graph = self._planning.get_plan(mission_id)
            if any(action.capability == new_capability for action in graph.actions.values()):
                return
        try:
            mission = self._orchestration.get(mission_id)
            self._planning.replan_for_change(
                mission_id,
                trigger=trigger,
                asset_key=mission.context.target_id,
                reason=f"observation from {capability}",
            )
        except Exception:  # noqa: BLE001 - replanning must never break the loop
            pass

    def _advance_state(self, mission_id: str) -> bool:
        """Advance the planning state when the current plan is exhausted.

        Returns ``True`` when the mission moved toward reassessment so the
        loop can re-decide (replanned follow-ons may now be ready).
        """
        mission = self._planning.get_mission(mission_id)
        non_terminal = [action for action in mission.graph.actions.values() if not action.status.is_terminal]
        if non_terminal:
            return False
        if mission.state is MissionState.REASSESSMENT:
            return False
        try:
            self._planning.transition(mission_id, MissionState.REASSESSMENT)
            return True
        except Exception:  # noqa: BLE001 - state advance is best-effort
            return False

    def _record_telemetry(self, mission_id: str) -> None:
        with contextlib.suppress(Exception):  # telemetry is best-effort
            self._orchestration.record_telemetry(mission_id)

    def _cycle_outcome(self, mission_id: str, **fields: Any) -> dict[str, Any]:
        return {"mission_id": mission_id, **fields}


__all__ = ["MissionExecutionService"]
