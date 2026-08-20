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

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_attack.enums import AttackState
from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    MissionState,
    ReplanTrigger,
)
from hunterx.domain.attack_surface.enums import (
    AssessmentStatus,
    CompletionVerdict,
    VerificationState,
)
from hunterx.domain.auth.session import AuthenticatedSession
from hunterx.domain.execution import ExecutionStatus
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import _endpoint_urls
from hunterx.domain.target_intelligence.enums import CoverageState
from hunterx.domain.vulnerability_capability.probe_executor import is_loopback_target
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.shared.masking import mask_value
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
    "javascript_analysis": "javascript",
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
    "javascript": ReplanTrigger.NEW_ENDPOINT_DISCOVERED,
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

def _as_list(value: Any) -> list[Any]:
    """Return ``value`` as a list (single values are wrapped)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _observation_id(observation: Any) -> str:
    """Return the observation id from either a model or its serialized dict."""
    if observation is None:
        return ""
    if isinstance(observation, dict):
        return str(observation.get("observation_id") or "")
    return str(getattr(observation, "observation_id", "") or "")


def _observed_status(result: Any) -> int | None:
    """Extract an observed HTTP status from an execution result's JSON payload.

    Tool outputs may carry a ``status_code``/``status`` for the target; a
    non-zero value is fed into the adaptive controller as target feedback.
    """
    output = getattr(result, "output", None)
    if output is None:
        return None
    data = getattr(output, "json", None)
    if not isinstance(data, dict):
        return None
    for key in ("status_code", "status"):
        value = data.get(key)
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return None


def _javascript_asset_urls(content: Any) -> list[str]:
    """Return script asset URLs (``*.js``/``*.mjs``) from an observation payload.

    Walks the discovery payload shapes (crawler ``crawl.urls`` records,
    ``urls``/``endpoints`` lists, direct ``url`` keys) and keeps only script
    paths — the assets the in-process javascript analysis capability should
    mine.
    """
    urls: list[str] = []
    candidates: list[str] = []
    if isinstance(content, list):
        candidates = [str(entry) for entry in content if entry]
    elif isinstance(content, dict):
        for key in ("urls", "endpoints"):
            candidates.extend(_urls_from_entries(content.get(key)))
        crawl = content.get("crawl")
        if isinstance(crawl, dict):
            candidates.extend(_urls_from_entries(crawl.get("urls")))
    else:
        return urls
    for url in candidates:
        from urllib.parse import urlsplit

        try:
            path = urlsplit(url).path
        except (ValueError, TypeError):
            continue
        if path.endswith(".js") or path.endswith(".mjs"):
            urls.append(url)
    return list(dict.fromkeys(urls))


def _urls_from_entries(value: Any) -> list[str]:
    """Return the string URLs of a discovery entries list (dicts or strings)."""
    urls: list[str] = []
    for entry in _as_list(value):
        item = entry.get("url") or entry.get("endpoint") if isinstance(entry, dict) else entry
        if item:
            urls.append(str(item).strip())
    return urls


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
        attack_surface: AttackSurfaceService | None = None,
        adaptive_attack: AdaptiveAttackService | None = None,
        adaptive_attack_factory: Any | None = None,
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
        #: Authenticated session established for the active mission (in-memory
        #: only, never persisted). ``None`` means no credentials were supplied
        #: or establishment failed; the scope label distinguishes the two.
        self._session: AuthenticatedSession | None = None
        #: ``True`` once session establishment has been attempted.
        self._auth_attempted: bool = False
        #: Masked establishment outcome shared with events (never raw secrets).
        self._auth_outcome: dict[str, Any] | None = None
        #: Target-agnostic attack-surface model/mapper/queue/gate for the active
        #: mission. Built per-mission unless injected (Phase 1). Never blocks
        #: the loop: every touch is best-effort.
        self._attack_surface: AttackSurfaceService | None = attack_surface
        #: Latest attack-surface exhaustion report (``None`` when not wired).
        self._surface_report: Any | None = None
        #: Aggressive-but-bounded adaptive attack controller (Phase 2). Built
        #: per-mission unless injected. Feeds execution outcomes back into the
        #: target-feedback state machine (aggression/pacing/backoff/retry).
        self._adaptive_attack: AdaptiveAttackService | None = adaptive_attack
        #: Optional per-mission factory ``(mission_id, target_key) -> service``
        #: for wiring a custom adaptive controller (tests/instrumentation).
        self._adaptive_attack_factory: Any | None = adaptive_attack_factory
        #: Bounded ceiling for a single pacing wait applied by the runner.
        self._pacing_cap_s: float = 5.0

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
        self._parameters = parameters or {}
        self._establish_auth_session(mission_id, parameters)
        self._seed_coverage(mission_id)
        self._build_attack_surface(mission_id)
        self._build_adaptive_attack(mission_id)
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
                # A numerical coverage/completion signal must not claim
                # completion while the plan still carries untested work
                # (replan-scheduled discovery such as javascript analysis, or
                # hypothesis-driven validation): keep executing until that work
                # is discharged.
                if (
                    stop.get("stop_condition")
                    in ("coverage_target_achieved", "high_value_hypotheses_resolved", "findings_validated")
                    and self._has_pending_plan_work(mission_id)
                ):
                    continue
                # A target that persistently blocks the assessment is never
                # "complete": keep a reduced (throttled) presence instead of
                # converting a defensive response into a success stop.
                if self._adaptive_blocked():
                    continue
                break
            # Phase 1 exhaustion gate: the attack surface is only complete when
            # discovery, dynamic re-discovery, all applicable capability×surface
            # combinations, the assessment queue and the verification queue are
            # exhausted and no new attack paths remain.
            if self._surface_exhausted(mission_id):
                break
        surface_report = self._surface_exhaustion_report(mission_id)
        if self._adaptive_blocked():
            finalize_condition: StopCondition | None = StopCondition.BLOCKED
        else:
            finalize_condition = self._surface_finalize_condition(mission_id, surface_report)
        self._finalize_run(mission_id, stop_condition=finalize_condition)
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
            "surface": surface_report.to_dict() if surface_report is not None else None,
            "adaptive_attack": self._adaptive_attack.snapshot() if self._adaptive_attack is not None else None,
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
        profile_tools: tuple[str, ...] = ()
        try:
            mission = self._orchestration.get(mission_id)
            objective = getattr(getattr(mission, "mission", None), "objective", "")
            objective_value = objective.value if hasattr(objective, "value") else str(objective or "")
            profile_tools = tuple(readiness.mission_profile_tools(objective_value))
        except Exception:  # noqa: BLE001 - profile resolution is best-effort
            profile_tools = ()
        try:
            return readiness.preflight(
                capabilities,
                mission_id=mission_id,
                auto_provision=auto_provision,
                profile_tools=profile_tools,
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
        # Replan actions bound to a specific asset (e.g. a discovered script
        # URL) execute against that asset; generic chain actions (no asset) run
        # against the mission target.
        target = action.asset or target
        action.mark(ActionStatus.RUNNING)
        self._attack_pace(mission_id)

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
        self._attack_observe(
            "",
            status_code=_observed_status(result),
            duration_ms=getattr(result, "duration_ms", 0) or 0,
            error=result.error or "",
            failure_kind=result.failure_kind.value if result.failure_kind else "",
            source="execution",
        )
        if result.ok:
            raw = self._observation_from_result(capability, result)
            ingested = self._orchestration.ingest_result(
                mission_id,
                tool_id=tool_id,
                action_id=action_id,
                asset_key=target,
                raw=raw,
            )
            self._surface_feedback(mission_id, raw, capability, target)
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
                self._surface_attack_paths(mission_id)
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
                form_raw: dict[str, Any] | None = None
                observed_status: int | None = None
                if capability == "parameter_discovery":
                    # Arjun enumerated no URL query parameters on this
                    # endpoint — but the page may still carry HTML form
                    # fields (POST forms are invisible to arjun). Extract
                    # them in-process so form-based surfaces produce
                    # parameter hypotheses and body-carrying probes. The
                    # observed HTTP status is recorded too: a restricted
                    # endpoint (404/401/402/502/...) becomes an
                    # access-control signal for the http-access-differential
                    # capability.
                    form_raw, observed_status = self._form_field_observation(mission_id, target)
                if (
                    observed_status is not None
                    and observed_status >= 400
                    and capability == "parameter_discovery"
                ):
                    # A restricted endpoint observed on the target surface is a
                    # candidate access barrier: record its status so the
                    # orchestrator derives an http-access-differential
                    # hypothesis that the capability probe verifies honestly.
                    status_raw: dict[str, Any] = {
                        "observation_type": "endpoint",
                        "content": {"status_code": int(observed_status), "endpoint": target},
                        "tool_id": "crawler",
                        "confidence": 1.0,
                    }
                    status_observation = self._orchestration.ingest_result(
                        mission_id,
                        tool_id="crawler",
                        action_id=action_id,
                        asset_key=target,
                        raw=status_raw,
                    )
                    self._surface_feedback(mission_id, status_raw, capability, target)
                    # Probe the freshly derived access-control hypothesis in the
                    # same cycle: the differential probe decides meaningful
                    # access (never a status change alone).
                    self._assess_hypotheses_after_observation(
                        mission_id,
                        action_id=action_id,
                        capability=capability,
                        observation=status_observation,
                        raw=status_raw,
                        result=result,
                    )
                if form_raw:
                    ingested = self._orchestration.ingest_result(
                        mission_id,
                        tool_id="crawler",
                        action_id=action_id,
                        asset_key=target,
                        raw=form_raw,
                    )
                    self._surface_feedback(mission_id, form_raw, capability, target)
                    self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
                    self._assess_hypotheses_after_observation(
                        mission_id,
                        action_id=action_id,
                        capability=capability,
                        observation=ingested,
                        raw=form_raw,
                        result=result,
                    )
                    self._replan_from_observation(mission_id, capability, form_raw, observation=ingested)
                    self._sync_phase(mission_id)
                    self._publish_tool_completed(
                        mission_id, action_id, capability, "crawler", target, result, outcome="evidence"
                    )
                    return self._cycle_outcome(
                        mission_id,
                        status="completed",
                        action_id=action_id,
                        capability=capability,
                        tool_id="crawler",
                        observation_type="parameter",
                    )
                if observed_status is not None and observed_status >= 400:
                    # The endpoint is restricted but carried no forms: the
                    # status observation above already fed the access-control
                    # hypothesis derivation; record coverage and move on.
                    self._record_coverage(mission_id, target, capability, tool_id, state=CoverageState.TESTED)
                    self._sync_phase(mission_id)
                    self._publish_tool_completed(
                        mission_id, action_id, capability, "crawler", target, result, outcome="evidence"
                    )
                    return self._cycle_outcome(
                        mission_id,
                        status="completed",
                        action_id=action_id,
                        capability=capability,
                        tool_id="crawler",
                        observation_type="endpoint",
                    )
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
        self._attack_observe(
            mission_id,
            status_code=None,
            error=error,
            failure_kind=failure_kind,
            source="execution",
        )
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

        The raw mission target (e.g. ``http://host.example:8080/app``) is
        normalized once and handed to each adapter in the shape its descriptor
        declares: web tools receive the full URL, host/domain/network tools
        receive the bare host. Passing a URL to a host tool silently produces
        empty results — a false "no findings" — so the shape must match the
        tool, never the operator's typing.
        """
        spec = normalize_target(target)
        declared = self._declared_targets(tool_id)
        effective_target = target_for_adapter(spec, declared)
        merged = dict(parameters or {})
        # Credentials are an execution-time input, never tool parameters: strip
        # the raw auth block and inject only the value-bearing session surface
        # (cookies/headers) so every tool context carries the authenticated
        # scope while raw secrets never reach contexts, events or dashboards.
        merged.pop("auth", None)
        session = self._session
        if session is not None and session.established:
            merged["cookies"] = dict(session.cookies)
            if session.headers:
                merged["headers"] = dict(session.headers)
        # The adaptive controller's bounded aggression tier is exposed to tool
        # adapters so richer applicable strategies are selected while healthy.
        if self._adaptive_attack is not None:
            merged["aggression"] = self._adaptive_attack.aggression_level().value
        return (
            ExecutionContextBuilder(tool_id=tool_id, target=effective_target)
            .with_mission(mission_id)
            .with_target_type(target_type_for(spec, declared))
            .with_permissions(self._permissions_for(tool_id))
            .with_parameters(merged)
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

    def _establish_auth_session(
        self,
        mission_id: str,
        parameters: dict[str, Any] | None,
    ) -> None:
        """Establish an authenticated session when credentials are configured.

        Reads the ``auth`` parameter block (``login_url``, ``username``,
        ``password``, optional ``extra_fields``) supplied through the approved
        env/config mechanism, performs a generic form login against the
        loopback target and keeps the session in memory for the mission. The
        outcome is published (masked) and recorded on the mission as an
        observation — an explicit failure is an honest negative, never a
        blocker.
        """
        self._auth_attempted = False
        self._session = None
        self._auth_outcome = None
        auth = parameters.get("auth") if isinstance(parameters, dict) else None
        if not isinstance(auth, dict):
            return
        login_url = str(auth.get("login_url") or "").strip()
        username = str(auth.get("username") or "").strip()
        password = str(auth.get("password") or "")
        if not login_url or not username or not password:
            self._auth_outcome = {"status": "skipped", "reason": "incomplete auth configuration"}
            self._publish(
                "auth.session.skipped",
                {"mission_id": mission_id, "reason": "incomplete auth configuration"},
            )
            return
        try:
            from hunterx.domain.vulnerability_capability.probe_executor import is_loopback_target

            if not is_loopback_target(login_url):
                self._auth_outcome = {
                    "status": "refused",
                    "reason": "login target is not a loopback target",
                }
                self._publish(
                    "auth.session.refused",
                    {"mission_id": mission_id, "reason": "login target is not a loopback target"},
                )
                return
        except Exception:  # noqa: BLE001 - guard degrades to attempt
            pass
        self._auth_attempted = True
        session = AuthenticatedSession(error="session establishment not attempted")
        try:
            from hunterx.application.session import SessionService

            session = SessionService().establish(
                login_url=login_url,
                username=username,
                password=password,
                extra_fields=auth.get("extra_fields") if isinstance(auth.get("extra_fields"), dict) else None,
            )
        except Exception as exc:  # noqa: BLE001 - establishment failures are recorded, never raised
            session = AuthenticatedSession(origin="", login_url=login_url, error=str(exc))
        self._session = session if session.established else None
        self._auth_outcome = {
            "status": "established" if session.established else "failed",
            "origin": session.origin,
            "reason": "" if session.established else session.error,
        }
        self._publish(
            "auth.session.established" if session.established else "auth.session.failed",
            {
                "mission_id": mission_id,
                "login_url": login_url,
                "scope": session.scope_label(),
                "username": mask_value(session.username, reveal_head=1, reveal_tail=0),
                "reason": "" if session.established else session.error,
            },
        )
        with contextlib.suppress(Exception):  # observation recording is best-effort
            self._orchestration.ingest_result(
                mission_id,
                capability="authentication_analysis",
                result={
                    "kind": "auth_session",
                    "content": (
                        f"authenticated session established for {session.origin}"
                        if session.established
                        else f"authentication failed for {login_url}: {session.error}"
                    ),
                },
                tool_id="session-service",
            )

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

    def _has_pending_plan_work(self, mission_id: str) -> bool:
        """Return ``True`` when the plan still holds untested discovery work.

        Only non-hypothesis-bound actions count as pending discovery work
        (replan-scheduled surface expansion such as javascript analysis, or
        unstarted chain capabilities). Hypothesis-bound validation nodes are
        already accounted for by the policy's open-hypothesis gates, so a
        mission with only those left may legitimately complete.

        Pending authenticated work is represented here too: when credentials
        are configured, session establishment runs before the first discovery
        cycle, so the authenticated discovery pass is exactly this plan's
        pending actions — the gate never lets the mission complete while that
        authenticated work is still pending.
        """
        try:
            graph = self._planning.get_plan(mission_id)
        except Exception:  # noqa: BLE001 - best-effort guard
            return False
        return any(
            action.status in (ActionStatus.PROPOSED, ActionStatus.APPROVED, ActionStatus.RUNNING)
            and not action.hypothesis_id
            for action in graph.actions.values()
        )

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
        elif trigger is ReplanTrigger.NEW_ENDPOINT_DISCOVERED:
            # Per-endpoint parameter discovery: every freshly discovered URL
            # gets its own DISCOVER_PARAMETERS action (deduplicated by
            # capability+asset below), so a multi-page surface is enumerated
            # parameter-by-parameter instead of a single mission-level run on
            # the target root. The planner's ``_on_new_endpoint`` already binds
            # the action to ``asset_key``, which is how the per-endpoint arjun
            # invocations reach each page's own form/URL surface.
            details = [
                {"endpoint": str(url)}
                for url in _endpoint_urls(content)
                if str(url).strip()
            ]
        elif new_capability:
            details = [{}]
        graph = self._planning.get_plan(mission_id)
        # Script assets a crawler observation surfaces (``*.js``/``*.mjs``) are
        # scheduled for in-process javascript analysis — one action per asset —
        # so SPA bundles are mined for API/search endpoints. This must run
        # BEFORE the generic follow-on dedup below, which may already have the
        # chain-scheduled capability in the graph.
        if trigger is ReplanTrigger.NEW_ENDPOINT_DISCOVERED:
            for js_url in _javascript_asset_urls(content):
                if any(
                    action.capability == "javascript_analysis" and action.asset == js_url
                    for action in graph.actions.values()
                ):
                    continue
                try:
                    self._planning.replan_for_change(
                        mission_id,
                        trigger=ReplanTrigger.JAVASCRIPT_ANALYSIS,
                        asset_key=js_url,
                        reason=f"script asset observed from {capability}",
                    )
                    self._check_replanned_readiness(mission_id)
                except Exception:  # noqa: BLE001 - replanning must never break the loop
                    continue
        if not details:
            return
        for detail in details:
            replan_asset = ""
            if trigger is ReplanTrigger.NEW_HYPOTHESIS_CREATED:
                # Per-hypothesis validation actions are distinct: dedup against
                # ANY existing action bound to the SAME hypothesis (terminal or
                # not) so an open hypothesis never respawns endless probes.
                if any(
                    action.hypothesis_id == detail.get("hypothesis_id")
                    for action in graph.actions.values()
                ):
                    continue
            elif detail.get("endpoint"):
                # Per-endpoint follow-on (parameter discovery on a discovered
                # URL): dedup by capability+asset so each endpoint is scheduled
                # at most once while every endpoint still gets its own action.
                endpoint = str(detail["endpoint"])
                if any(
                    action.capability == new_capability and action.asset == endpoint
                    for action in graph.actions.values()
                ):
                    continue
                replan_asset = endpoint
            else:
                if any(action.capability == new_capability for action in graph.actions.values()):
                    # Generic follow-on capabilities are scheduled at most once.
                    continue
                replan_asset = ""
            try:
                mission = self._orchestration.get(mission_id)
                self._planning.replan_for_change(
                    mission_id,
                    trigger=trigger,
                    asset_key=replan_asset or mission.context.target_id,
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
            "observed_status": str(provenance.get("observed_status") or ""),
            "proof_marker": str(provenance.get("proof_marker") or ""),
        }
        # A POST-discovered form field must be probed through a request body:
        # the provenance records the method (``POST``/``PUT``) the surface was
        # observed with, and the capability builds body-carrying probes.
        method = str(provenance.get("method") or "").strip().upper()
        if method in ("POST", "PUT"):
            evidence["method"] = method
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
            # An established session reaches the authenticated surface: attach
            # the session cookies/headers to the probe so the differential runs
            # authenticated (an anonymous probe would hit the login wall and
            # produce a false negative).
            if self._session is not None and self._session.established:
                probe = self._with_session_headers(probe)
            self._publish(
                "vulnerability.probe.started",
                {
                    "mission_id": mission_id,
                    "vulnerability_class": vulnerability_class,
                    "endpoint": execution_target,
                    "parameter": parameter,
                    "scope": "authenticated"
                    if self._session is not None and self._session.established
                    else "anonymous",
                },
            )
            responses = ProbeExecutor().execute(probe, target=execution_target)
            self._probe_feedback(responses)
            if (
                self._session is not None
                and self._session.established
                and _landed_on_auth_wall(responses)
            ):
                # An established session can expire mid-mission (an authenticated
                # crawl can touch a logout endpoint). The login wall is never
                # target evidence: re-establish the session and retry the probe
                # once so the differential runs against the real surface.
                self._establish_auth_session(mission_id, self._parameters)
                if self._session is not None and self._session.established:
                    probe = self._with_session_headers(probe)
                    responses = ProbeExecutor().execute(probe, target=execution_target)
                    self._probe_feedback(responses)
                if _landed_on_auth_wall(responses):
                    # The session could not be re-established: record the probe
                    # honestly as inconclusive (no signal was evaluated against
                    # the login wall) and leave the hypothesis open.
                    self._orchestration.record_probe(
                        mission_id,
                        vulnerability_class=vulnerability_class,
                        endpoint=execution_target,
                        parameter=parameter,
                        signal="unauthenticated",
                        supported=False,
                        contradicted=False,
                        notes="probe landed on the authentication wall; session could not be re-established",
                        payload_count=len(probe.payloads),
                        response_summary=_probe_response_summary(responses),
                        evidence_ref=f"probe:{vulnerability_class}:{execution_target}",
                    )
                    return None
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

    def _with_session_headers(self, probe: Any) -> Any:
        """Return a copy of ``probe`` carrying the established session headers.

        Existing probe headers are kept; the session ``Cookie`` (and any extra
        session headers) are merged in last so nothing the class-specific probe
        already set is overwritten.
        """
        from dataclasses import replace

        session = self._session
        if session is None or not session.established:
            return probe
        headers: list[tuple[str, str]] = list(getattr(probe, "headers", ()) or ())
        cookie = session.cookie_header()
        if cookie:
            headers = [pair for pair in headers if pair[0].lower() != "cookie"]
            headers.append(("Cookie", cookie))
        for name, value in session.headers:
            if any(existing[0].lower() == name.lower() for existing in headers):
                continue
            headers.append((name, value))
        return replace(probe, headers=tuple(headers))

    def _session_probe_headers(self) -> tuple[tuple[str, str], ...]:
        """Return the session's probe headers (empty tuple when no session).

        Used to pass the authenticated scope into the finding service's
        verification and replay probes.
        """
        session = self._session
        if session is None or not session.established:
            return ()
        headers: list[tuple[str, str]] = []
        cookie = session.cookie_header()
        if cookie:
            headers.append(("Cookie", cookie))
        headers.extend(session.headers)
        return tuple(headers)

    def _form_field_observation(
        self, mission_id: str, endpoint: str
    ) -> tuple[dict[str, Any] | None, int | None]:
        """Return ``(parameter_observation, observed_status)`` for ``endpoint``.

        Arjun enumerates URL query parameters; HTML form fields (notably POST
        forms) are invisible to it, so a form-only surface (e.g. a POST-only
        command-execution form) never produces a parameter hypothesis and is
        never assessed. The in-process HTML parser extracts form field names —
        generically, for any form-based endpoint — so body-carrying
        differential probes can assess those surfaces. The observed HTTP
        status is returned alongside (even when no forms exist) so a
        restricted endpoint (404/401/402/502/...) is recorded as an
        access-control signal for the http-access-differential capability.
        ``(None, None)`` when the endpoint cannot be fetched.
        """
        try:
            from hunterx.domain.vulnerability_capability.probe_executor import is_loopback_target
            from hunterx.domain.web.parsers import extract_forms
            from hunterx.tools.web.httpclient import HttpPageFetcher

            if not is_loopback_target(endpoint):
                return None, None
            cookies = (
                dict(self._session.cookies)
                if self._session is not None and self._session.established
                else None
            )
            fetcher = HttpPageFetcher()
            page = fetcher.fetch(endpoint, cookies=cookies) if cookies else fetcher.fetch(endpoint)
            for _hop in range(5):
                if not page.is_redirect or not page.redirect_url or not is_loopback_target(page.redirect_url):
                    break
                page = fetcher.fetch(page.redirect_url, cookies=cookies) if cookies else fetcher.fetch(page.redirect_url)
            status = page.status_code
            if page.status_code != 200 or not page.content:
                return None, status
            findings: list[dict[str, str]] = []
            for form in extract_forms(page.content, endpoint):
                action = str(form.get("action") or endpoint)
                method = str(form.get("method") or "GET").upper()
                for field in form.get("fields") or []:
                    name = str(field.get("name") or "").strip()
                    if name:
                        findings.append({"name": name, "endpoint": action, "method": method})
            if not findings:
                return None, status
            return (
                {
                    "observation_type": "parameter",
                    "content": {"parameters": {"findings": findings}},
                    "tool_id": "crawler",
                    "confidence": 1.0,
                },
                status,
            )
        except Exception:  # noqa: BLE001 - form extraction is best-effort discovery
            return None, None

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
            provenance = f"hypothesis:{hypothesis.hypothesis_id}"
            existing = [
                item
                for item in service.list_findings(mission_id)
                if item.get("provenance") == provenance
            ]
            if existing:
                finding = existing[0]
            else:
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
                    provenance=provenance,
                    scope=_finding_scope_for_hypothesis(hypothesis, endpoint),
                )
        except Exception as exc:  # noqa: BLE001 - materialization is best-effort
            self._publish("finding.materialization.failed", {"mission_id": mission_id, "reason": str(exc)})
            return
        if str(finding.get("status") or "") == "report_ready":
            self._publish(
                "finding.materialized",
                {"mission_id": mission_id, "finding_id": finding["finding_id"], "status": "report_ready", "report_ready": True, "result": {}},
            )
            return
        try:
            result = service.complete_validated_finding(
                finding["finding_id"],
                probe_headers=self._session_probe_headers(),
            )
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

    def _build_attack_surface(self, mission_id: str) -> None:
        """Build (or keep) the per-mission attack-surface service.

        The surface model is mission-scoped; an injected instance is reused,
        otherwise a fresh one is built for the active mission's target.
        """
        if self._attack_surface is not None:
            return
        with contextlib.suppress(Exception):  # surface modelling must never block the loop
            mission = self._orchestration.get(mission_id)
            target_key = mission.context.target_id or "target"
            self._attack_surface = AttackSurfaceService(
                mission_id=mission_id,
                target_key=target_key,
                event_bus=self._event_bus,
            )

    def _build_adaptive_attack(self, mission_id: str) -> None:
        """Build (or keep) the per-mission adaptive attack controller.

        The controller is mission-scoped; an injected instance or a wired
        factory is used, otherwise a fresh one is built for the active
        mission's target.
        """
        if self._adaptive_attack is not None:
            return
        with contextlib.suppress(Exception):  # adaptive control must never block the loop
            mission = self._orchestration.get(mission_id)
            target_key = mission.context.target_id or "target"
            if self._adaptive_attack_factory is not None:
                self._adaptive_attack = self._adaptive_attack_factory(mission_id, target_key)
            else:
                self._adaptive_attack = AdaptiveAttackService(
                    mission_id=mission_id,
                    target_key=target_key,
                    event_bus=self._event_bus,
                )

    def _adaptive_blocked(self) -> bool:
        """Return ``True`` when the adaptive controller is in ``BLOCKED``.

        A persistently blocking target must never be reported as a success
        stop — blocking is blocking, not completion.
        """
        service = self._adaptive_attack
        if service is None:
            return False
        with contextlib.suppress(Exception):
            return service.attack_state() is AttackState.BLOCKED
        return False

    def _attack_observe(
        self,
        mission_id: str,
        *,
        status_code: int | None = None,
        duration_ms: int = 0,
        error: str = "",
        failure_kind: str = "",
        body_hint: str = "",
        source: str = "execution",
    ) -> None:
        """Feed an execution outcome into the adaptive attack controller.

        Defensive responses (429/403/5xx/timeout/connection/latency/WAF)
        throttle the engine; they are target feedback, never mission
        completion. Any failure degrades to no-op.
        """
        service = self._adaptive_attack
        if service is None:
            return
        with contextlib.suppress(Exception):
            service.observe(
                status_code=status_code,
                duration_ms=duration_ms,
                error=error,
                failure_kind=failure_kind,
                body_hint=body_hint,
                source=source,
            )

    def _attack_pace(self, mission_id: str) -> None:
        """Apply the adaptive controller's bounded pacing before the next step.

        Pacing is only enforced when the controller is wired and requests it
        (throttled/backing-off/blocked states); the wait is capped so a
        defensive target can never cause an uncontrolled stall.
        """
        service = self._adaptive_attack
        if service is None or not service.enforce_pacing:
            return
        delay = service.pacing_seconds()
        if delay <= 0:
            return
        import time

        time.sleep(min(delay, self._pacing_cap_s))

    def _probe_feedback(self, responses: Any) -> None:
        """Feed differential-probe responses into the adaptive controller."""
        service = self._adaptive_attack
        if service is None or not responses:
            return
        status = 0
        duration = 0
        for response in responses:
            if not isinstance(response, dict):
                continue
            response_status = int(response.get("status") or 0)
            if response_status in (429, 403) or response_status >= 500:
                status = response_status
            duration = max(duration, int(response.get("elapsed_ms") or 0))
        if status:
            self._attack_observe("", status_code=status, duration_ms=duration, source="probe")
        elif duration:
            self._attack_observe("", duration_ms=duration, source="probe")

    def _surface_feedback(
        self,
        mission_id: str,
        raw: dict[str, Any],
        capability: str,
        target: str,
    ) -> None:
        """Feed an observation into the attack-surface model (best-effort).

        The surface service classifies the observation, upserts surface nodes,
        maps ``Capability × Surface × Context`` and schedules assessment tasks.
        Any failure degrades to no-op so the mission loop is never blocked by
        surface modelling.
        """
        surface = self._attack_surface
        if surface is None:
            return
        with contextlib.suppress(Exception):
            session_state = ""
            if self._session is not None:
                session_state = str(getattr(self._session, "state", "") or "")
            surface.on_observation(
                observation_type=str(raw.get("observation_type", "")),
                content=raw.get("content"),
                asset_key=target,
                capability=capability,
                source="mission_execution",
                session_state=session_state,
            )
            self._discharge_assessments(surface, capability, target, has_meaningful_content(raw.get("content")), mission_id)
            self._surface_report = surface.exhaustion()

    def _discharge_assessments(
        self,
        surface: AttackSurfaceService,
        capability: str,
        target: str,
        meaningful: bool,
        mission_id: str,
    ) -> None:
        """Execute queued assessments — real probes on probeable targets.

        Loopback targets run through the capability execution engine so every
        queued ``Capability × Surface × Context`` assessment is discharged with
        real differential probes and an honest verdict. Non-probeable targets
        fall back to evidence-backed bookkeeping so remote missions can still
        reach exhaustion. Any failure degrades to no-op (never blocks the loop).
        """
        if not capability:
            return
        if is_loopback_target(target):
            self._execute_assessments(surface, mission_id, target)
            return
        self._settle_assessments(surface, capability, target, meaningful)

    def _execute_assessments(self, surface: AttackSurfaceService, mission_id: str, target: str) -> None:
        """Run every ready assessment through the capability execution engine."""
        from hunterx.application.capability_execution import CapabilityExecutionEngine

        engine = CapabilityExecutionEngine(
            mission_id=mission_id,
            target_key=target,
            surface=surface,
            adaptive=self._adaptive_attack,
        )
        engine.execute_ready(session=self._session)

    def _settle_assessments(
        self,
        surface: AttackSurfaceService,
        capability: str,
        target: str,
        meaningful: bool,
    ) -> None:
        """Discharge queued assessments a completed capability actually covered.

        When the planner executes a capability against an asset, the
        corresponding ``(surface, capability)`` assessment is discharged:
        evidence-backed observations settle it ``VERIFIED``, empty ones
        ``NOT_APPLICABLE``. Discharging is what lets the completion gate reach
        exhaustion once every mapped combination has been evaluated.
        """
        if not capability:
            return
        node_keys = {node.key for node in surface.graph.nodes() if node.name == str(target)}
        if not node_keys:
            return
        state = VerificationState.VERIFIED if meaningful else VerificationState.NOT_APPLICABLE
        for task in surface.queue.tasks():
            if task.capability_id != capability or task.surface_key not in node_keys:
                continue
            surface.queue.mark(task.task_id, AssessmentStatus.COMPLETED)
            surface.queue.settle(task.task_id, state)
        for node_key in node_keys:
            for assignment in surface.graph.assignments_for(node_key):
                if assignment.capability_id == capability:
                    assignment.mark(AssessmentStatus.COMPLETED)
                    assignment.settle(state)

    def _surface_attack_paths(self, mission_id: str) -> None:
        """Feed the attack-path count into the completion gate (best-effort)."""
        surface = self._attack_surface
        if surface is None:
            return
        with contextlib.suppress(Exception):
            mission = self._orchestration.get(mission_id)
            surface.record_attack_paths(len(mission.context.attack_paths))

    def _surface_exhausted(self, mission_id: str) -> bool:
        """Return ``True`` when the attack surface is genuinely exhausted.

        Exhaustion only counts once discovery, dynamic discovery, all applicable
        capability/surface combinations, the assessment queue and the
        verification queue are done — and the planning graph carries no
        untested work.
        """
        surface = self._attack_surface
        if surface is None:
            return False
        with contextlib.suppress(Exception):
            report = surface.exhaustion()
            self._surface_report = report
            return report.verdict is CompletionVerdict.EXHAUSTED and not self._has_pending_plan_work(mission_id)
        return False

    def _surface_exhaustion_report(self, mission_id: str) -> Any | None:
        """Return (and cache) the latest attack-surface exhaustion report."""
        surface = self._attack_surface
        if surface is None:
            return None
        with contextlib.suppress(Exception):
            self._surface_report = surface.exhaustion()
        return self._surface_report

    def _surface_finalize_condition(self, mission_id: str, report: Any | None) -> StopCondition | None:
        """Return the exhaustion stop condition when genuinely exhausted.

        A budget/terminal exhaustion is never overwritten by the surface gate,
        so resource limits stay truthful.
        """
        if report is None or report.verdict is not CompletionVerdict.EXHAUSTED:
            return None
        with contextlib.suppress(Exception):
            mission = self._orchestration.get(mission_id)
            if mission.mission.state.is_terminal or mission.budget.exhausted:
                return None
        return StopCondition.ATTACK_SURFACE_EXHAUSTED

    def _finalize_run(self, mission_id: str, *, stop_condition: StopCondition | None = None) -> None:
        """Finalize the mission run (idempotent) so no run stays ``running``."""
        with contextlib.suppress(Exception):  # attack-path recording is best-effort
            self._orchestration.record_attack_paths(mission_id)
        with contextlib.suppress(Exception):  # finalization is the terminal step
            self._orchestration.finalize(
                mission_id,
                stop_condition=stop_condition.value if stop_condition is not None else None,
            )

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


def _landed_on_auth_wall(responses: list[dict[str, Any]]) -> bool:
    """Return ``True`` when probe responses landed on the authentication wall.

    An authenticated probe whose final (post-redirect) responses resolve to a
    login page means the session was lost mid-mission — the login page is not
    target evidence and must never be evaluated as one.
    """
    return any("login" in str(response.get("url") or "") for response in (responses or []))


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


def _finding_scope_for_hypothesis(hypothesis: Any, endpoint: str) -> dict[str, Any] | None:
    """Derive the finding scope from an access/response-differential hypothesis.

    Carries the observed status, the proof marker and the mutation request/method
    so the finding service can probe, verify and reproduce the bypass.
    """
    provenance = dict(hypothesis.provenance or {})
    if str(provenance.get("vulnerability_class") or "") != "http-access-differential":
        return None
    observed_status = provenance.get("observed_status")
    proof_marker = provenance.get("proof_marker")
    scope: dict[str, Any] = {}
    if observed_status:
        scope["observed_status"] = str(observed_status)
    if proof_marker:
        scope["proof_marker"] = str(proof_marker)
        try:
            from urllib.parse import urlsplit

            path = urlsplit(endpoint).path or "/"
            scope["reproduction_request"] = f"{endpoint}{'' if endpoint.endswith('/') else '/'}"
            scope["reproduction_method"] = "GET"
            scope["mutation_path"] = path + "/"
        except (ValueError, TypeError):
            pass
    return scope or None


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
