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
from hunterx.shared.target import (
    has_meaningful_content,
    normalize_target,
    target_for_adapter,
    target_type_for,
)
from hunterx.tools.recon.runner import (
    bind_active_execution,
    clear_active_execution,
)
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

def _observation_id(observation: Any) -> str:
    """Return the observation id from either a model or its serialized dict."""
    if observation is None:
        return ""
    if isinstance(observation, dict):
        return str(observation.get("observation_id") or "")
    return str(getattr(observation, "observation_id", "") or "")


#: Canonical MissionState the planning engine advances through as work is
#: completed. ``_advance_state`` walks one legal hop per exhausted plan so the
#: mission never gets stuck in reassessment while work remains.
_FORWARD_STATES: tuple[MissionState, ...] = (
    MissionState.SCOPING,
    MissionState.DISCOVERY,
    MissionState.ENUMERATION,
    MissionState.MAPPING,
    MissionState.ANALYSIS,
    MissionState.HYPOTHESIS_GENERATION,
    MissionState.VALIDATION,
    MissionState.PROOF,
    MissionState.REASSESSMENT,
    MissionState.REPORTING,
    MissionState.COMPLETED,
)

#: Capability → planning state mapping used to move out of REASSESSMENT into
#: the phase that actually contains the next scheduled work.
_STATE_BY_CAPABILITY: dict[str, MissionState] = {
    "asset_discovery": MissionState.DISCOVERY,
    "subdomain_enumeration": MissionState.DISCOVERY,
    "dns_enumeration": MissionState.DISCOVERY,
    "port_discovery": MissionState.ENUMERATION,
    "service_detection": MissionState.ENUMERATION,
    "technology_fingerprint": MissionState.ANALYSIS,
    "certificate_enumeration": MissionState.MAPPING,
    "endpoint_enumeration": MissionState.MAPPING,
    "content_discovery": MissionState.MAPPING,
    "parameter_discovery": MissionState.ANALYSIS,
    "api_mapping": MissionState.MAPPING,
    "authentication_analysis": MissionState.ANALYSIS,
    "authorization_analysis": MissionState.VALIDATION,
    "vulnerability_scanning": MissionState.HYPOTHESIS_GENERATION,
    "sql_injection": MissionState.VALIDATION,
    "xss": MissionState.VALIDATION,
    "ssrf": MissionState.VALIDATION,
    "ssti": MissionState.VALIDATION,
    "xxe": MissionState.VALIDATION,
    "lfi": MissionState.VALIDATION,
    "rce": MissionState.VALIDATION,
    "idor": MissionState.VALIDATION,
    "api_security": MissionState.VALIDATION,
    "graphql_security": MissionState.VALIDATION,
    "secret_detection": MissionState.VALIDATION,
    "dependency_check": MissionState.VALIDATION,
    "cloud_ownership_mapping": MissionState.MAPPING,
    "proof_validation": MissionState.PROOF,
    "replay": MissionState.PROOF,
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
        ai_suggester: Any | None = None,
        finding_service: Any | None = None,
    ) -> None:
        self._orchestration = orchestration
        self._planning = planning
        self._engine = execution_engine
        self._event_bus = event_bus
        self._readiness = readiness
        #: Vulnerability finding orchestration service (optional). When wired, a
        #: probe-verified hypothesis produces a full finding record with
        #: vulnerability evidence, reproduction, PoC, replay and report-ready.
        self._finding_service = finding_service
        #: Capabilities vetted by the mission preflight. Replanned capabilities
        #: outside this set are re-checked before execution (Defect 3).
        self._preflight_capabilities: set[str] = set()
        #: Advisory AI action-suggestion producer (None keeps the mission
        #: fully deterministic — the AI is never required for execution).
        self._ai_suggester = ai_suggester
        #: Last orchestration phase announced via ``mission.phase.started`` so
        #: phase changes are emitted once (live CLI visibility).
        self._last_phase: str = ""

    # -- public API ---------------------------------------------------------

    def execute_cycle(self, mission_id: str, *, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        """Run one Observe → Decide → Act → Observe cycle for ``mission_id``.

        Returns a JSON-safe cycle outcome describing the decision, the tool
        execution attempt and its outcome. Never marks a running mission as
        complete just because a single cycle finished.

        When an AI suggestion producer is wired, an advisory suggestion is
        requested and passed to the decision engine. The deterministic engine
        remains the final authority; a rejected or unavailable AI proposal is
        ignored and the deterministic planner continues.
        """
        mission = self._orchestration.get(mission_id)
        if mission.mission.state.is_terminal:
            return self._cycle_outcome(mission_id, status="skipped", reason="mission terminal")
        self._approve_ready_actions(mission_id)
        ai_suggestion, ai_reason, ai_trace = self._request_ai_suggestion(mission_id)
        decision = self._orchestration.decide_next(
            mission_id,
            ai_suggestion=ai_suggestion,
            ai_reason=ai_reason,
        )
        if decision is not None and ai_trace:
            self._record_ai_trace(mission_id, decision, ai_trace)
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
        is reached. Completion is never claimed merely because the initial
        discovery plan has been walked: only the terminal exit finalizes the
        mission.

        When a tool-readiness service is wired, a mission preflight runs first:
        required capabilities without an available provider (and whose
        provisioning fails) return a structured ``blocked`` outcome and the
        mission never enters active execution. Missing optional capabilities
        degrade the outcome but do not stop the loop.

        Every terminal exit path finalizes the mission: the run record is
        marked COMPLETED with a ``finished_at`` timestamp and the planning
        state walks to COMPLETED, so no mission is ever left ``running`` when
        the runner returns.
        """
        preflight = self._preflight(mission_id, auto_provision=auto_provision)
        if preflight is not None:
            self._publish(
                "mission.preflight.completed",
                {
                    "mission_id": mission_id,
                    "status": preflight.status.value,
                    "reason": getattr(preflight, "blocked_reason", "") or "",
                },
            )
        if preflight is not None and not preflight.may_execute:
            self._publish("mission.blocked", {"mission_id": mission_id, "reason": preflight.blocked_reason})
            self._finalize_run(mission_id)
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
        self._finalize_run(mission_id)
        self._record_telemetry(mission_id)
        mission = self._orchestration.get(mission_id)
        return {
            "mission_id": mission_id,
            "cycles_run": len(cycles),
            "cycles": cycles,
            "planning_state": mission.mission.state.value,
            "status": _run_status(mission, preflight),
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
        self._preflight_capabilities = set(capabilities)
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
            context = self._build_context(mission_id, tool_id, target, parameters)
            bind_active_execution(
                tool_id=tool_id,
                mission_id=mission_id,
                execution_id=context.execution_id,
                capability=capability,
                action_id=action_id,
                target=target,
            )
            self._publish(
                "mission.tool.started",
                {
                    "mission_id": mission_id,
                    "action_id": action_id,
                    "tool_id": tool_id,
                    "capability": capability,
                    "target": target,
                    "execution_id": context.execution_id,
                },
            )
            pipeline = engine.execute(context)
        except Exception as exc:  # noqa: BLE001 - surfaced as a structured failure
            return self._fail_execution(
                mission_id,
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                error=str(exc),
            )
        finally:
            clear_active_execution()
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
            ingested = self._orchestration.ingest_result(
                mission_id,
                tool_id=tool_id,
                action_id=action_id,
                asset_key=target,
                raw=raw,
            )
            self._planning.get_action(mission_id, action_id).mark(ActionStatus.COMPLETED)
            meaningful = has_meaningful_content(raw.get("content"))
            if meaningful:
                self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
                # Evidence-driven reassessment: update the hypotheses this
                # probe was designed to test, then let the planner reconsider.
                self._assess_hypotheses_after_observation(
                    mission_id,
                    action_id=action_id,
                    capability=capability,
                    observation=ingested,
                    raw=raw,
                    result=result,
                )
                self._replan_from_observation(mission_id, capability, raw, observation=ingested)
                self._sync_phase(mission_id)
                # Attack paths are intelligence derived from the discovered
                # surface — recorded as the mission moves through
                # discovery → hypothesis → probe (never triggers execution).
                with contextlib.suppress(Exception):  # attack-path recording is best-effort
                    self._orchestration.record_attack_paths(mission_id)
                self._publish_tool_completed(
                    mission_id, action_id, capability, tool_id, target, result, outcome="evidence"
                )
                return self._cycle_outcome(
                    mission_id,
                    status="completed",
                    action_id=action_id,
                    capability=capability,
                    tool_id=tool_id,
                    observation_type=raw.get("observation_type", ""),
                )
            if _is_explicit_negative(result):
                self._orchestration.record_negative(
                    mission_id,
                    asset_key=target,
                    capability=capability,
                    kind="tested",
                    tool_id=tool_id,
                    outcome="explicit empty result",
                    notes="tool executed successfully and reported no findings",
                )
                self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
                self._sync_phase(mission_id)
                self._publish_tool_completed(
                    mission_id, action_id, capability, tool_id, target, result, outcome="negative"
                )
                return self._cycle_outcome(
                    mission_id,
                    status="completed",
                    action_id=action_id,
                    capability=capability,
                    tool_id=tool_id,
                    observation_type=raw.get("observation_type", ""),
                    negative_evidence=True,
                )
            # An empty-but-successful execution carries no evidence: it is an
            # uninformative result, never an assessment of the target.
            self._record_coverage(
                mission_id,
                target,
                capability,
                tool_id,
                state=CoverageState.NOT_ASSESSED,
                notes="empty/uninformative result; no meaningful evidence",
            )
            self._sync_phase(mission_id)
            self._publish_tool_completed(
                mission_id, action_id, capability, tool_id, target, result, outcome="uninformative"
            )
            return self._cycle_outcome(
                mission_id,
                status="completed",
                action_id=action_id,
                capability=capability,
                tool_id=tool_id,
                observation_type=raw.get("observation_type", ""),
                uninformative=True,
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
        # A failed/blocked execution is NOT an assessment: leaving the cell
        # NOT_ASSESSED keeps it uncovered so it can never satisfy a coverage
        # target as if the capability had actually been exercised. Only a
        # genuinely successful execution records TESTED coverage.
        self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.NOT_ASSESSED)
        self._publish(
            "mission.tool.failed",
            {
                "mission_id": mission_id,
                "action_id": action_id,
                "tool_id": tool_id,
                "capability": capability,
                "target": target,
                "error": error[:2000],
                "failure_kind": failure_kind,
                "status": status_value,
                "exit_code": exit_code,
            },
        )
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
        """Build the execution context with a scheme-aware per-tool target.

        The raw mission target (e.g. ``http://localhost:3010``) is normalized
        once and handed to each adapter in the shape its descriptor declares:
        web tools receive the full URL, host/domain/network tools receive the
        bare host. Passing a URL to a host tool silently produces empty results
        — a false "no findings" — so the shape must match the tool, never the
        operator's typing.
        """
        spec = normalize_target(target)
        declared = self._declared_targets(tool_id)
        effective_target = target_for_adapter(spec, declared)
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=effective_target)
            .with_mission(mission_id)
            .with_target_type(target_type_for(spec, declared))
            .with_permissions(self._permissions_for(tool_id))
            .with_parameters(dict(parameters or {}))
        ).build()

    def _declared_targets(self, tool_id: str) -> tuple[str, ...]:
        """Return the target kinds the tool's adapter declares."""
        engine = self._engine
        adapter_for = getattr(engine, "adapter_for", None)
        if engine is None or adapter_for is None:
            return ()
        adapter = adapter_for(tool_id)
        if adapter is None:
            return ()
        descriptor = getattr(adapter, "descriptor", None)
        if descriptor is None:
            return ()
        targets = getattr(descriptor, "targets", ())
        return tuple(targets) if targets else ()

    def _permissions_for(self, tool_id: str) -> tuple[str, ...]:
        """Return the permissions the selected tool's adapter declares.

        The sandbox denies any execution whose context does not explicitly
        grant the adapter-requested permission flags (network/filesystem/...).
        Without this the mission runner would create a context with an empty
        permission set and every network-capable tool would be rejected before
        it can run. This mirrors the adapter-permission resolution used by the
        ad-hoc tool execution and chain-execution paths.

        Engines that do not expose the adapter API (deterministic test fakes)
        fall back to a no-permission context — they do not enforce the sandbox,
        so the granted set is only relevant for the real execution engine.
        """
        engine = self._engine
        adapter_for = getattr(engine, "adapter_for", None)
        if engine is None or adapter_for is None:
            return ("none",)
        adapter = adapter_for(tool_id)
        if adapter is None:
            return ("none",)
        requested = tuple(getattr(getattr(adapter, "descriptor", None), "permissions", ()) or ())
        # An adapter with no declared permissions is a no-permission execution.
        return requested or ("none",)

    def _request_ai_suggestion(self, mission_id: str) -> tuple[str, str, dict[str, Any]]:
        """Request an advisory AI suggestion for the next action.

        Returns ``(suggestion_action_id, suggestion_reason, trace)``. When no
        AI producer is wired, or the producer/response fails, the suggestion is
        empty and the mission continues deterministically. The ``trace`` dict
        records AI invocation/provenance for telemetry (empty when not invoked).
        """
        if self._ai_suggester is None:
            return "", "", {}
        mission = self._orchestration.get(mission_id)
        candidates = self._ready_candidates(mission)
        suggestion = self._ai_suggester.suggest(mission, candidates)
        trace = {
            "ai_invoked": suggestion.invoked,
            "ai_latency_ms": suggestion.latency_ms,
            "ai_suggestion": suggestion.action_id,
            "ai_reason": suggestion.reason,
            "ai_error": suggestion.error,
            "ai_usable": suggestion.usable,
        }
        return suggestion.action_id, suggestion.reason, trace

    def _ready_candidates(self, mission: Any) -> list[Any]:
        """Return the currently ready candidate actions for the mission plan."""
        if self._planning is None:
            return []
        try:
            graph = self._planning.get_plan(mission.mission_id)
            return graph.ready_actions(approved_only=True)
        except Exception:  # noqa: BLE001 - candidate collection is best-effort
            return []

    def _record_ai_trace(self, mission_id: str, decision: Any, trace: dict[str, Any]) -> None:
        """Record the AI-invocation provenance for a decision (best-effort).

        The decision may be a dict (application layer) or a domain decision
        record; both expose ``ai_assisted``. The trace is recorded on the
        mission via the orchestration engine's reasoning-trace facility.
        """
        decision_id = decision.get("decision_id", "") if isinstance(decision, dict) else getattr(decision, "decision_id", "")
        trace = dict(trace)
        trace["ai_assisted"] = (
            decision.get("ai_assisted", False) if isinstance(decision, dict) else getattr(decision, "ai_assisted", False)
        )
        with contextlib.suppress(Exception):  # provenance recording is best-effort
            self._orchestration.record_ai_trace(mission_id, decision_id=decision_id, **trace)

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
        notes: str = "",
    ) -> None:
        with contextlib.suppress(Exception):  # coverage is best-effort telemetry
            self._orchestration.record_coverage(
                mission_id,
                asset_key=asset_key or "target",
                capability=capability,
                state=state,
                tool_id=tool_id,
                confidence=0.7 if state is CoverageState.TESTED else 0.0,
                notes=notes,
            )
            # Live coverage visibility: announce tested cells and any cell
            # with an explanation. The initial NOT_ASSESSED seed pass carries
            # no notes and stays silent (no fake progress).
            if state is CoverageState.TESTED or notes:
                self._publish(
                    "coverage.updated",
                    {
                        "mission_id": mission_id,
                        "asset_key": asset_key or "target",
                        "capability": capability,
                        "state": state.value,
                        "tool_id": tool_id,
                        "notes": notes,
                    },
                )

    def _replan_from_observation(
        self,
        mission_id: str,
        capability: str,
        raw: dict[str, Any],
        observation: Any | None = None,
    ) -> None:
        """Let the planner reconsider the mission from the new observation.

        Replanning is deduplicated: a capability already present in the live
        graph (non-terminal) is never scheduled twice. Replanning only fires on
        observations that carry meaningful evidence — an empty result never
        schedules follow-on work.

        A ``NEW_HYPOTHESIS_CREATED`` signal binds the follow-on validation node
        to the hypothesis that the observation produced, so the next decision
        ranks an evidence-driven probe (and never a generic capability).
        """
        trigger = _TRIGGER_BY_OBSERVATION.get(str(raw.get("observation_type", "")))
        if trigger is None:
            return
        content = raw.get("content")
        if not content or not has_meaningful_content(content):
            return
        new_capability = _CAPABILITY_BY_TRIGGER.get(trigger, "")
        details: list[dict[str, Any]] = []
        if trigger is ReplanTrigger.NEW_HYPOTHESIS_CREATED:
            for hypothesis_id in self._hypotheses_from_observation(mission_id, observation):
                details.append({"hypothesis_id": hypothesis_id, "capability": "vulnerability_scanning"})
        elif new_capability:
            details = [{}]
        if not details:
            return
        graph = self._planning.get_plan(mission_id)
        for detail in details:
            if trigger is ReplanTrigger.NEW_HYPOTHESIS_CREATED:
                # Per-hypothesis validation actions are distinct: dedup against
                # ANY existing action bound to the SAME hypothesis (terminal or
                # not) so an open hypothesis never respawns endless probes.
                if any(
                    action.hypothesis_id == detail.get("hypothesis_id")
                    for action in graph.actions.values()
                ):
                    continue
            elif any(action.capability == new_capability for action in graph.actions.values()):
                # Generic follow-on capabilities are scheduled at most once.
                return
            try:
                mission = self._orchestration.get(mission_id)
                self._planning.replan_for_change(
                    mission_id,
                    trigger=trigger,
                    asset_key=mission.context.target_id,
                    detail=detail or None,
                    reason=f"observation from {capability}",
                )
            except Exception:  # noqa: BLE001 - replanning must never break the loop
                continue
            # Replanned work may introduce capabilities the preflight never
            # vetted: re-check readiness before any of it executes.
            self._check_replanned_readiness(mission_id)

    def _hypothesis_from_observation(self, mission_id: str, observation: Any | None) -> str:
        """Return the hypothesis supported by ``observation``, if any.

        The hypothesis was created by the orchestrator from the same
        observation (its ``supporting_evidence`` references the observation id);
        the highest-priority candidate is returned.
        """
        if observation is None:
            return ""
        try:
            mission = self._orchestration.get(mission_id)
        except Exception:  # noqa: BLE001 - best-effort lookup
            return ""
        observation_id = _observation_id(observation)
        candidates = [
            hypothesis
            for hypothesis in mission.hypotheses
            if observation_id and observation_id in hypothesis.supporting_evidence
        ]
        if not candidates:
            return ""
        return sorted(candidates, key=lambda h: (-h.priority, -h.confidence))[0].hypothesis_id

    def _hypotheses_from_observation(self, mission_id: str, observation: Any | None) -> list[str]:
        """Return every hypothesis supported by ``observation``.

        Multiple candidates in one observation produce multiple class-specific
        hypotheses; each gets its own targeted validation action so chaining
        across classes works (not just the highest-priority one).
        """
        if observation is None:
            return []
        try:
            mission = self._orchestration.get(mission_id)
        except Exception:  # noqa: BLE001 - best-effort lookup
            return []
        observation_id = _observation_id(observation)
        candidates = [
            hypothesis
            for hypothesis in mission.hypotheses
            if observation_id and observation_id in hypothesis.supporting_evidence
        ]
        return [
            hypothesis.hypothesis_id
            for hypothesis in sorted(candidates, key=lambda h: (-h.priority, -h.confidence))[:40]
        ]

    def _assess_hypotheses_after_observation(
        self,
        mission_id: str,
        *,
        action_id: str,
        capability: str,
        observation: Any,
        raw: dict[str, Any],
        result: Any,
    ) -> None:
        """Update hypotheses the executed probe was designed to test.

        Every class-specific hypothesis supported by the observation is assessed
        (not just the highest-priority one), so a crawler URL with several
        query parameters (``?to=``, ``?q=``) drives a targeted probe for each.
        A meaningful result is supporting evidence; an explicit negative is
        contradicting evidence. When a hypothesis reaches SUPPORTED it is
        independently verified, and when it validates the linked CANDIDATE
        finding is promoted to ``verified``.
        """
        action = None
        try:
            action = self._planning.get_action(mission_id, action_id)
        except Exception:  # noqa: BLE001 - best-effort lookup
            action = None
        bound = getattr(action, "hypothesis_id", "") if action is not None else ""
        hypothesis_ids = self._hypotheses_from_observation(mission_id, observation)
        if bound and bound not in hypothesis_ids:
            hypothesis_ids.insert(0, bound)
        # Attack-surface-derived hypotheses (created from the endpoint/parameter
        # context) carry no observation reference; assess them too so their
        # targeted differential probes actually run.
        for hypothesis_id in self._unbound_vulnerability_hypotheses(mission_id):
            if hypothesis_id not in hypothesis_ids:
                hypothesis_ids.append(hypothesis_id)
        for hypothesis_id in hypothesis_ids[:12]:
            self._assess_hypothesis(
                mission_id,
                hypothesis_id=hypothesis_id,
                action_id=action_id,
                observation=observation,
                raw=raw,
                result=result,
            )

    def _unbound_vulnerability_hypotheses(self, mission_id: str) -> list[str]:
        """Return open vulnerability-class hypotheses with no bound action.

        Used so targeted probes are scheduled for hypotheses derived from the
        attack-surface model even when no observation directly references them.
        """
        try:
            mission = self._orchestration.get(mission_id)
            graph = self._planning.get_plan(mission_id)
        except Exception:  # noqa: BLE001 - best-effort
            return []
        bound = {action.hypothesis_id for action in graph.actions.values() if action.hypothesis_id}
        result: list[str] = []
        for hypothesis in mission.hypotheses:
            if hypothesis.hypothesis_id in bound:
                continue
            if hypothesis.state.value in ("validated", "refuted", "disproved", "rejected"):
                continue
            if (hypothesis.provenance or {}).get("vulnerability_class"):
                result.append(hypothesis.hypothesis_id)
        return result

    def _assess_hypothesis(
        self,
        mission_id: str,
        *,
        hypothesis_id: str,
        action_id: str,
        observation: Any,
        raw: dict[str, Any],
        result: Any,
    ) -> None:
        """Assess a single hypothesis against the observation/probe evidence."""
        try:
            mission = self._orchestration.get(mission_id)
        except Exception:  # noqa: BLE001 - best-effort assessment
            return
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            return
        if hypothesis.state.value in ("validated", "refuted", "disproved", "rejected"):
            # A settled hypothesis is never downgraded by further observations.
            return
        observation_id = _observation_id(observation)
        supporting: tuple[str, ...] = ()
        contradicting: tuple[str, ...] = ()
        # Class-specific differential analysis: when the hypothesis targets a
        # vulnerability class and the mission target is an authorized loopback
        # host, the capability engine runs a baseline-vs-payload probe and the
        # verdict (not "any tool output") decides support or contradiction.
        verdict = self._differential_verdict(mission_id, hypothesis)
        if verdict is not None:
            vulnerability_class = str((hypothesis.provenance or {}).get("vulnerability_class") or "")
            if verdict.supported:
                # The differential probe is independent evidence, distinct from
                # the tool observation that created the hypothesis.
                probe_ref = f"probe:{vulnerability_class}:{str((hypothesis.provenance or {}).get('endpoint') or '')}"
                supporting = tuple(dict.fromkeys(filter(None, (observation_id, probe_ref))))
            elif verdict.contradicted:
                # A class-specific probe found no signal: the hypothesis for
                # that class is refuted (honest negative), never validated.
                with contextlib.suppress(Exception):
                    self._orchestration.refute_hypothesis(
                        mission_id,
                        hypothesis_id,
                        reason=verdict.notes,
                        tested_action=action_id,
                    )
                    self._publish(
                        "vulnerability.hypothesis.updated",
                        {
                            "mission_id": mission_id,
                            "hypothesis_id": hypothesis_id,
                            "vulnerability_class": vulnerability_class,
                            "state": "refuted",
                            "signal": verdict.signal.value,
                        },
                    )
                return
            else:
                return
        elif has_meaningful_content(raw.get("content")):
            supporting = (observation_id,) if observation_id else ()
        elif _is_explicit_negative(result):
            contradicting = (observation_id,) if observation_id else ()
        else:
            return
        try:
            updated = self._orchestration.update_hypothesis(
                mission_id,
                hypothesis_id,
                supporting=supporting,
                contradicting=contradicting,
                tested_action=action_id,
            )
        except Exception:  # noqa: BLE001 - hypothesis updates must never break the loop
            return
        new_state = updated.get("state") if isinstance(updated, dict) else getattr(updated, "state", "")
        new_state = getattr(new_state, "value", new_state)
        vulnerability_class = str((hypothesis.provenance or {}).get("vulnerability_class") or "")
        if verdict is not None and vulnerability_class:
            self._publish(
                "vulnerability.hypothesis.updated",
                {
                    "mission_id": mission_id,
                    "hypothesis_id": hypothesis_id,
                    "vulnerability_class": vulnerability_class,
                    "state": new_state,
                    "signal": verdict.signal.value,
                },
            )
        if new_state == "supported":
            # Independent verification is the only evidence that may validate
            # a hypothesis. Meaningful scanner output moves a hypothesis to
            # SUPPORTED but can never validate it: without a supporting
            # differential-probe verdict the finding stays CANDIDATE/SUPPORTED
            # and never becomes a verified/validated vulnerability.
            if verdict is not None and verdict.supported:
                with contextlib.suppress(Exception):
                    verified = self._orchestration.verify_hypothesis(mission_id, hypothesis_id)
                    verified_state = verified.get("state") if isinstance(verified, dict) else getattr(verified, "state", "")
                    verified_state = getattr(verified_state, "value", verified_state)
                    if verified_state == "validated":
                        self._promote_findings_for_hypothesis(mission_id, hypothesis_id)
        elif new_state in ("refuted", "disproved", "rejected"):
            # The hypothesis was disproven by the probe: no finding promotion.
            statement = updated.get("statement") if isinstance(updated, dict) else getattr(updated, "statement", "")
            self._publish(
                "mission.hypothesis.updated",
                {
                    "mission_id": mission_id,
                    "hypothesis_id": hypothesis_id,
                    "state": new_state,
                    "statement": statement,
                },
            )

    def _differential_verdict(self, mission_id: str, hypothesis: Any) -> Any | None:
        """Run a class-specific differential probe for a vulnerability hypothesis.

        Returns a :class:`ProbeVerdict`, or ``None`` when the hypothesis is not
        class-specific, no probe can be built, or the target is not an
        authorized loopback host. The verdict is advisory evidence for the
        hypothesis state — it never fabricates a finding by itself.
        """
        provenance = dict(hypothesis.provenance or {})
        vulnerability_class = str(provenance.get("vulnerability_class") or "")
        if not vulnerability_class:
            return None
        try:
            mission = self._orchestration.get(mission_id)
        except Exception:  # noqa: BLE001 - best-effort
            return None
        target = mission.context.target_id or ""
        if not target:
            return None
        endpoint = str(provenance.get("endpoint") or target)
        parameter = str(provenance.get("parameter") or "")
        evidence = {
            "target": target,
            "endpoint": endpoint,
            "parameter": parameter,
            "confidence": hypothesis.confidence,
        }
        try:
            from hunterx.domain.vulnerability_capability.engine import VulnerabilityCapabilityEngine
            from hunterx.domain.vulnerability_capability.probe_executor import ProbeExecutor

            engine = VulnerabilityCapabilityEngine()
            probe = engine.build_probe(vulnerability_class, evidence)
            if probe is None:
                return None
            from hunterx.domain.vulnerability_capability.probe_executor import is_loopback_target

            # Scope guard on the mission target, but execute the probe against
            # the specific endpoint (which carries the path/parameter surface).
            if not is_loopback_target(target):
                return None
            execution_target = endpoint or target
            if not is_loopback_target(execution_target):
                return None
            self._publish(
                "vulnerability.probe.started",
                {
                    "mission_id": mission_id,
                    "vulnerability_class": vulnerability_class,
                    "endpoint": execution_target,
                    "parameter": parameter,
                },
            )
            responses = ProbeExecutor().execute(probe, target=execution_target)
            verdict = engine.analyze_probe(vulnerability_class, probe, responses)
            # Persist the probe execution as a first-class observation. This
            # records that a TARGETED PROBE ran and what it observed — it is
            # advisory probe evidence, NOT vulnerability evidence. Vulnerability
            # evidence (BEHAVIORAL_DIFFERENTIAL / ...) is only persisted on the
            # finding record when the verdict supports the class.
            self._orchestration.record_probe(
                mission_id,
                vulnerability_class=vulnerability_class,
                endpoint=execution_target,
                parameter=parameter,
                signal=verdict.signal.value,
                supported=verdict.supported,
                contradicted=verdict.contradicted,
                notes=verdict.notes,
                payload_count=len(probe.payloads),
                response_summary=_probe_response_summary(responses),
                evidence_ref=f"probe:{vulnerability_class}:{execution_target}",
            )
            self._publish(
                "vulnerability.probe.completed",
                {
                    "mission_id": mission_id,
                    "vulnerability_class": vulnerability_class,
                    "signal": verdict.signal.value,
                    "supported": verdict.supported,
                    "contradicted": verdict.contradicted,
                    "notes": verdict.notes,
                },
            )
            return verdict
        except PermissionError:
            return None
        except Exception:  # noqa: BLE001 - differential probing is best-effort
            return None

    def _promote_findings_for_hypothesis(self, mission_id: str, hypothesis_id: str) -> None:
        """Promote CANDIDATE findings linked to a validated hypothesis to verified.

        A tool output is never a vulnerability: the finding is only promoted
        when the evidence-driven hypothesis that explains it has been
        independently validated. When a validated hypothesis has no matching
        candidate finding (e.g. it was derived from a discovered parameter), a
        verified finding is created from the hypothesis itself — always with
        the probe/observation provenance.
        """
        try:
            mission = self._orchestration.get(mission_id)
            hypothesis = mission.hypothesis(hypothesis_id)
        except Exception:  # noqa: BLE001 - promotion is best-effort
            return
        if hypothesis is None:
            return
        asset_key = str((hypothesis.provenance or {}).get("asset_key", ""))
        endpoint = str((hypothesis.provenance or {}).get("endpoint") or "")
        parameter = str((hypothesis.provenance or {}).get("parameter") or "")
        promoted = False
        for finding in list(mission.context.findings):
            if finding.get("stage") != "candidate":
                continue
            finding_hypothesis = finding.get("hypothesis_id")
            if finding_hypothesis and finding_hypothesis != hypothesis_id:
                continue
            if not finding_hypothesis and asset_key and finding.get("asset_key") not in (None, "", asset_key):
                continue
            with contextlib.suppress(Exception):
                self._orchestration.register_finding(
                    mission_id,
                    finding_id=finding["finding_id"],
                    vulnerability_class=finding.get("vulnerability_class", ""),
                    title=finding.get("title", ""),
                    description=finding.get("description", ""),
                    asset_key=finding.get("asset_key", ""),
                    target=finding.get("target", ""),
                    severity=finding.get("severity", "info"),
                    tool=finding.get("tool", ""),
                    stage="verified",
                    evidence_refs=tuple(finding.get("evidence_refs") or ()),
                    confidence=finding.get("confidence", 0.0) or 0.0,
                )
                self._publish(
                    "vulnerability.finding.validated",
                    {
                        "mission_id": mission_id,
                        "finding_id": finding["finding_id"],
                        "vulnerability_class": finding.get("vulnerability_class", ""),
                        "hypothesis_id": hypothesis_id,
                    },
                )
                promoted = True
        if not promoted:
            # A validated hypothesis with no candidate finding (parameter-derived)
            # becomes a verified finding with full provenance.
            vulnerability_class = str((hypothesis.provenance or {}).get("vulnerability_class") or "")
            if vulnerability_class:
                with contextlib.suppress(Exception):
                    finding = self._orchestration.register_finding(
                        mission_id,
                        vulnerability_class=vulnerability_class,
                        title=f"{vulnerability_class} on {endpoint or asset_key}",
                        description=(
                            f"validated by a differential probe ({hypothesis.statement}); "
                            f"hypothesis {hypothesis_id}"
                        ),
                        asset_key=endpoint or asset_key or mission.context.target_id or "target",
                        target=mission.context.target_id or "",
                        severity="high",
                        tool="hunterx-capability",
                        stage="verified",
                        evidence_refs=(hypothesis_id, *hypothesis.supporting_evidence),
                        confidence=hypothesis.confidence,
                    )
                    if isinstance(finding, dict) and finding.get("finding_id"):
                        self._publish(
                            "vulnerability.finding.validated",
                            {
                                "mission_id": mission_id,
                                "finding_id": finding["finding_id"],
                                "vulnerability_class": vulnerability_class,
                                "hypothesis_id": hypothesis_id,
                                "parameter": parameter,
                            },
                        )
        # Bridge to the finding orchestration service: the validated,
        # probe-verified hypothesis also produces the full finding record
        # (vulnerability evidence, reproduction, PoC, real replay,
        # report-ready). The finding is downstream of the actual probe
        # verdict — it is never fabricated from the target alone.
        self._materialize_validated_finding(mission_id, hypothesis)

    def _materialize_validated_finding(self, mission_id: str, hypothesis: Any) -> None:
        """Create the full validated finding through the finding service.

        The finding service re-runs the targeted differential probe as the
        explicit verification step, persists vulnerability evidence, builds
        reproduction + PoC, replays the probe against the target (real
        re-execution) and only then marks the finding REPORT_READY. If the
        probe no longer supports the class, the finding stays at
        CANDIDATE/SUPPORTED — no success is fabricated.
        """
        service = self._finding_service
        if service is None:
            return
        try:
            vulnerability_class = str((hypothesis.provenance or {}).get("vulnerability_class") or "")
            if not vulnerability_class:
                return
            endpoint = str((hypothesis.provenance or {}).get("endpoint") or "")
            parameter = str((hypothesis.provenance or {}).get("parameter") or "")
            mission = self._orchestration.get(mission_id)
            if not endpoint:
                endpoint = mission.context.target_id or ""
            if not endpoint:
                return
            class_value = vulnerability_class.replace("-", "_")
            finding = service.create_finding(
                mission_id=mission_id,
                target_id=mission.context.target_id or "",
                asset_id="",
                asset=endpoint,
                vulnerability_class=class_value,
                title=f"{vulnerability_class} on {endpoint}",
                description=(
                    f"validated by a targeted differential probe ({hypothesis.statement}); "
                    f"hypothesis {hypothesis.hypothesis_id}"
                ),
                severity="high",
                tool="hunterx-capability",
                endpoints=(endpoint,),
                parameters=(parameter,) if parameter else (),
                observations=[
                    {
                        "kind": "detection_signature",
                        "value": f"candidate from hypothesis {hypothesis.hypothesis_id}",
                        "quality": "medium",
                        "source": "mission",
                    }
                ],
                provenance=f"hypothesis:{hypothesis.hypothesis_id}",
            )
        except Exception as exc:  # noqa: BLE001 - materialization is best-effort
            self._publish("finding.materialization.failed", {"mission_id": mission_id, "reason": str(exc)})
            return
        try:
            result = service.complete_validated_finding(finding["finding_id"])
        except Exception as exc:  # noqa: BLE001 - best-effort completion
            result = {"error": str(exc)}
        # When the finding service confirms report-readiness, reflect it on the
        # mission-context finding so the mission dashboard/report are truthful.
        report_ready = bool(
            isinstance(result, dict)
            and result.get("validated")
            and result.get("report_ready", {}).get("transition", {}).get("allowed")
        )
        if report_ready:
            with contextlib.suppress(Exception):  # best-effort context sync
                target_class = str((hypothesis.provenance or {}).get("vulnerability_class") or "")
                target_asset = endpoint or ""
                for context_finding in mission.context.findings:
                    if context_finding.get("vulnerability_class") != target_class:
                        continue
                    finding_asset = str(context_finding.get("asset_key") or "")
                    if finding_asset != target_asset and target_asset != finding_asset:
                        continue
                    self._orchestration.register_finding(
                        mission_id,
                        finding_id=context_finding["finding_id"],
                        vulnerability_class=context_finding.get("vulnerability_class", ""),
                        title=context_finding.get("title", ""),
                        description=context_finding.get("description", ""),
                        asset_key=finding_asset,
                        target=context_finding.get("target", ""),
                        severity=context_finding.get("severity", "info"),
                        tool=context_finding.get("tool", ""),
                        stage="report_ready",
                        evidence_refs=tuple(context_finding.get("evidence_refs") or ()),
                        confidence=context_finding.get("confidence", 0.0) or 0.0,
                    )
                    break
        self._publish(
            "finding.materialized",
            {
                "mission_id": mission_id,
                "finding_id": finding["finding_id"],
                "status": result.get("status") if isinstance(result, dict) else "error",
                "report_ready": report_ready,
                "result": result,
            },
        )

    def _check_replanned_readiness(self, mission_id: str) -> None:
        """Re-check readiness for capabilities the preflight did not vet.

        The preflight gate only sees the initial plan. A replan that schedules
        a new capability (e.g. vulnerability scanning) must re-probe its
        providers before execution: an unavailable provider leaves the cell
        NOT_ASSESSED with a clear reason, a broken provider records the actual
        probe failure. No negative evidence is manufactured here.
        """
        readiness = self._readiness
        if readiness is None:
            return
        graph = self._planning.get_plan(mission_id)
        probe = getattr(readiness, "check", None)
        if not callable(probe):
            return
        for action in list(graph.actions.values()):
            if action.status.is_terminal:
                continue
            capability = action.capability
            if capability in self._preflight_capabilities:
                continue
            tool_ids = _candidate_tools(action)
            if not tool_ids:
                # A freshly replanned action has no bound candidates yet (the
                # capability-aware selector binds them at approval time): fall
                # back to the capability's default candidate families so the
                # readiness verdict is the true ground truth for the plan.
                tools = getattr(self._planning, "tools", None)
                candidates = getattr(tools, "default_candidates", None) if tools is not None else None
                if isinstance(candidates, dict):
                    tool_ids = [str(tool) for tool in candidates.get(capability, ())]
            if not tool_ids:
                continue
            verdict = None
            try:
                report = probe(list(tool_ids), sync_engine=True)
                by_tool = {v.tool_id: v for v in report.tools}
                verdict = next((by_tool[t] for t in tool_ids if t in by_tool), None)
            except Exception:  # noqa: BLE001 - readiness probing is best-effort
                verdict = None
            if verdict is not None and verdict.status.value == "available":
                continue
            reason = _readiness_reason(action.capability, verdict)
            with contextlib.suppress(Exception):  # action may already be terminal
                action.mark(ActionStatus.FAILED)
                self._planning.record_failure(
                    mission_id,
                    action.action_id,
                    tool_id=str(action.selected_tool or ""),
                    error=reason,
                )
            self._record_coverage(
                mission_id,
                self._orchestration.get(mission_id).context.target_id or "target",
                capability,
                str(action.selected_tool or ""),
                state=CoverageState.NOT_ASSESSED,
                notes=reason,
            )

    def _advance_state(self, mission_id: str) -> bool:
        """Advance the planning state toward the phase that holds the work.

        Returns ``True`` when the mission moved forward so the loop can
        re-decide. Advancement follows the canonical MissionState progression:
        a reassessed plan with remaining work moves into the phase that
        contains it; a plan with work in a later phase walks one legal hop
        toward it; an exhausted plan walks one hop forward.
        """
        mission = self._planning.get_mission(mission_id)
        state = mission.state
        if state is MissionState.COMPLETED:
            return False
        non_terminal = [action for action in mission.graph.actions.values() if not action.status.is_terminal]
        if state is MissionState.REASSESSMENT:
            if not non_terminal:
                return False
            target = _state_for_actions(non_terminal)
            if target is None or target is state:
                return False
            try:
                self._planning.transition(mission_id, target)
                self._sync_phase(mission_id)
                return True
            except Exception:  # noqa: BLE001 - state advance is best-effort
                return False
        if non_terminal:
            work_state = _state_for_actions(non_terminal)
            if work_state is None or work_state is state:
                return False
            if _state_rank(work_state) <= _state_rank(state):
                return False
            target = _next_forward_state(state)
            if target is None or target is MissionState.COMPLETED:
                return False
            if _state_rank(target) > _state_rank(work_state):
                return False
            try:
                self._planning.transition(mission_id, target)
                self._sync_phase(mission_id)
                return True
            except Exception:  # noqa: BLE001 - state advance is best-effort
                return False
        target = _next_forward_state(state)
        if target is None or target is MissionState.COMPLETED:
            return False
        try:
            self._planning.transition(mission_id, target)
            self._sync_phase(mission_id)
            return True
        except Exception:  # noqa: BLE001 - state advance is best-effort
            return False

    def _sync_phase(self, mission_id: str) -> None:
        """Synchronize the orchestration phase from the planning workflow state."""
        with contextlib.suppress(Exception):  # phase sync is best-effort
            phase = self._orchestration.sync_phase(mission_id)
            if phase and phase != self._last_phase:
                self._last_phase = phase
                self._publish(
                    "mission.phase.started",
                    {"mission_id": mission_id, "phase": phase, "phase_kind": phase},
                )

    def _finalize_run(self, mission_id: str) -> None:
        """Finalize the mission run (idempotent) so no run stays ``running``."""
        with contextlib.suppress(Exception):  # attack-path recording is best-effort
            self._orchestration.record_attack_paths(mission_id)
        with contextlib.suppress(Exception):  # finalization is the terminal step
            self._orchestration.finalize(mission_id)

    def _record_telemetry(self, mission_id: str) -> None:
        with contextlib.suppress(Exception):  # telemetry is best-effort
            self._orchestration.record_telemetry(mission_id)

    def _publish_tool_completed(
        self,
        mission_id: str,
        action_id: str,
        capability: str,
        tool_id: str,
        target: str,
        result: Any,
        *,
        outcome: str,
    ) -> None:
        """Publish the ``mission.tool.completed`` event for a finished tool."""
        self._publish(
            "mission.tool.completed",
            {
                "mission_id": mission_id,
                "action_id": action_id,
                "tool_id": tool_id,
                "capability": capability,
                "target": target,
                "execution_id": getattr(result, "execution_id", ""),
                "duration_ms": getattr(result, "duration_ms", 0) or 0,
                "exit_code": getattr(getattr(result, "output", None), "exit_code", 0),
                "outcome": outcome,
            },
        )

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        """Publish a runner-level event on the wired bus (best-effort).

        Event delivery is advisory for execution: a misbehaving subscriber (or
        a missing bus) must never break the mission loop, so publishing is
        best-effort and swallows failures.
        """
        bus = self._event_bus
        if bus is None:
            return
        from hunterx.domain.events import DomainEvent

        with contextlib.suppress(Exception):  # event delivery must never break execution
            bus.publish(
                DomainEvent(
                    event_type=event_type,
                    payload=payload,
                    source="application.mission_execution",
                    mission_id=str(payload.get("mission_id") or ""),
                )
            )

    def _cycle_outcome(self, mission_id: str, **fields: Any) -> dict[str, Any]:
        return {"mission_id": mission_id, **fields}


def _is_explicit_negative(result: Any) -> bool:
    """Return ``True`` for a structured, well-formed empty tool result.

    An explicit negative is a tool that executed successfully and produced
    structured output (JSON) reporting nothing — e.g. ``subfinder -d host``
    returning an empty JSON document. An empty stdout-only result is
    uninformative, never a validated negative.
    """
    output = getattr(result, "output", None)
    if output is None:
        return False
    if getattr(output, "json", None) is None:
        return False
    json_value = output.json
    if isinstance(json_value, dict):
        return not has_meaningful_content(json_value)
    if isinstance(json_value, list):
        return len(json_value) == 0
    return False


def _probe_response_summary(responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize probe responses (status + bounded body length) for recording.

    Only status codes and lengths are captured — never raw secret-bearing
    bodies — so the probe observation proves the differential without leaking
    sensitive response content.
    """
    return {
        "responses": [
            {
                "status": int(response.get("status") or 0),
                "body_length": len(str(response.get("body") or "")),
                "elapsed_ms": int(response.get("elapsed_ms") or 0),
            }
            for response in (responses or [])
        ]
    }


def _run_status(mission: Any, preflight: Any | None) -> str:
    """Derive the truthful run status from the finalized mission outcome.

    The status distinguishes completed / blocked / exhausted / failed /
    cancelled and never claims success when the objectives are incomplete.
    """
    if preflight is not None and preflight.status.value == "degraded":
        return "degraded"
    outcome = getattr(mission, "outcome", None)
    if outcome is None:
        return "blocked"
    if outcome.objectives_complete:
        return "completed"
    stop_condition = getattr(outcome, "stop_condition", "") or ""
    if stop_condition in ("resource_budget_exhausted", "time_budget_exhausted"):
        return "exhausted"
    if stop_condition == "unrecoverable_failure":
        return "failed"
    if stop_condition == "operator_cancelled":
        return "cancelled"
    return "blocked"


def _next_forward_state(current: MissionState) -> MissionState | None:
    """Return the next canonical forward state reachable from ``current``."""
    from hunterx.domain.adaptive_mission_planning.state import can_transition

    try:
        index = _FORWARD_STATES.index(current)
    except ValueError:
        return None
    for candidate in _FORWARD_STATES[index + 1 :]:
        if candidate is MissionState.REASSESSMENT:
            continue
        if candidate is MissionState.COMPLETED:
            if can_transition(current, candidate):
                return candidate
            continue
        if can_transition(current, candidate):
            return candidate
    return None


def _state_for_actions(actions: list[Any]) -> MissionState | None:
    """Return the earliest planning state that contains the given work."""
    states: list[MissionState] = []
    for action in actions:
        state = _STATE_BY_CAPABILITY.get(str(getattr(action, "capability", "")))
        if state is not None and state not in states:
            states.append(state)
    if not states:
        return None
    return min(states, key=_state_rank)


def _state_rank(state: MissionState) -> int:
    """Return the canonical forward rank of a planning state."""
    try:
        return _FORWARD_STATES.index(state)
    except ValueError:
        return len(_FORWARD_STATES)


def _candidate_tools(action: Any) -> list[str]:
    """Return the candidate tool ids of an action (selected first)."""
    selected = str(getattr(action, "selected_tool", "") or "")
    if selected:
        return [selected]
    candidates = tuple(getattr(action, "tool_candidate_set", ()) or ())
    return [str(tool) for tool in candidates] if candidates else []


def _readiness_reason(capability: str, verdict: Any) -> str:
    """Return a clear reason for an unavailable replanned capability."""
    status = getattr(verdict, "status", None)
    status_value = getattr(status, "value", status) if status is not None else "unavailable"
    if verdict is None or status_value in ("missing", "unknown", "unavailable"):
        return f"capability '{capability}' has no available provider after replan; not assessed"
    error = getattr(verdict, "error", "")
    if error:
        return f"capability '{capability}' provider probe failed: {error}"
    return f"capability '{capability}' provider unavailable ({status_value}); not assessed"


__all__ = ["MissionExecutionService"]
