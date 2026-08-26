# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission orchestrator engine.

Sprint 032. The stateful, adaptive, evidence-driven orchestrator. After EVERY
meaningful result it:

    1. Parses and normalizes the result into observations.
    2. Updates target state (context, coverage, negative evidence).
    3. Updates evidence and hypotheses (hypothesis loop).
    4. Recalculates the attack surface.
    5. Determines knowledge gaps.
    6. Determines candidate actions.
    7. Ranks actions (expected information gain).
    8. Selects the next action.

It never blindly continues a static DAG. It delegates plan mutation, attack
paths, tool selection and failure recovery to the Sprint 027 engine
(:class:`AdaptiveMissionPlanningEngine`) and adds the reasoning/evidence layer
on top.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
    ActionStatus,
    MissionMode,
    MissionObjective,
    MissionState,
)
from hunterx.domain.adaptive_mission_planning.mission import AdaptiveMission
from hunterx.domain.mission_orchestration.baseline import (
    BaselineEngine,
    BaselineObservation,
    DifferentialTestEngine,
    TestResponse,
)
from hunterx.domain.mission_orchestration.branch import BranchManager
from hunterx.domain.mission_orchestration.cascade import CascadeTrigger, FindingCascadeEngine
from hunterx.domain.mission_orchestration.confidence import (
    ConfidenceEngine,
    ConfidenceInput,
    ConfidenceResult,
)
from hunterx.domain.mission_orchestration.coverage import MissionCoverageEngine
from hunterx.domain.mission_orchestration.decision import (
    CandidateAction,
    DecisionInput,
    MissionDecisionEngine,
)
from hunterx.domain.mission_orchestration.enums import (
    BehaviorClass,
    FindingStage,
    HypothesisState,
    MissionEventType,
    MissionPhase,
    MissionRunStatus,
    NovelPipelineStage,
    ReasoningTraceKind,
    StopCondition,
    StrategyKind,
)
from hunterx.domain.mission_orchestration.gap import KnowledgeGap, KnowledgeGapEngine
from hunterx.domain.mission_orchestration.hypothesis import HypothesisLoopEngine
from hunterx.domain.mission_orchestration.impact import ImpactAnalysisEngine
from hunterx.domain.mission_orchestration.mission import (
    OrchestratedMission,
    new_orchestrated_mission,
)
from hunterx.domain.mission_orchestration.models import (
    ImpactAnalysis,
    MissionBranch,
    MissionDecision,
    MissionHypothesis,
    MissionObservation,
    MissionOutcome,
    MissionPolicy,
    MissionRun,
    MissionScope,
    NegativeEvidenceRecord,
    NovelBehaviorRecord,
)
from hunterx.domain.mission_orchestration.negative import NegativeEvidenceEngine
from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine, PolicyVerdict
from hunterx.domain.mission_orchestration.telemetry import MissionTelemetry
from hunterx.domain.mission_orchestration.trace import ReasoningTrace
from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    CoverageState,
    HypothesisType,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.target import has_meaningful_content
from hunterx.shared.time import utcnow_iso

#: Resource-governed bounds for attack-path graph construction.
#
# ``record_attack_paths`` rebuilds an attack-surface graph from the mission
# context after EVERY meaningful observation. A port-scan observation can add
# hundreds of ``context.services`` entries, and a crawler hundreds of
# endpoints; the graph then links each service to each endpoint (a dense
# bipartite adjacency) which the attack-path BFS explores. Without bounds this
# is a transient memory/CPU bomb (the real 5.6 GiB runaway). These caps keep
# the analysis bounded: only the most relevant services/endpoints participate
# in attack-path discovery, and the BFS itself is visit-capped. The durable
# system of record (TIDB) keeps the full discovery; only the in-memory analysis
# graph is bounded.
_MAX_ATTACK_PATH_SERVICES = 64
_MAX_ATTACK_PATH_ENDPOINTS = 200


class MissionOrchestrator:
    """Runtime facade of the autonomous mission orchestration layer.

    The orchestrator composes the pure engines (hypothesis loop, decision,
    baseline, differential, negative evidence, coverage, knowledge gap,
    confidence, branches, telemetry, trace, policies, impact, cascade) over the
    Sprint 027 adaptive planning engine. It is injected, never constructed with
    concrete tool implementations.
    """

    def __init__(
        self,
        *,
        planning: Any | None = None,
        hypothesis_loop: HypothesisLoopEngine | None = None,
        decision: MissionDecisionEngine | None = None,
        baseline: BaselineEngine | None = None,
        differential: DifferentialTestEngine | None = None,
        negative: NegativeEvidenceEngine | None = None,
        coverage: MissionCoverageEngine | None = None,
        gaps: KnowledgeGapEngine | None = None,
        confidence: ConfidenceEngine | None = None,
        branches: BranchManager | None = None,
        telemetry: MissionTelemetry | None = None,
        trace: ReasoningTrace | None = None,
        policy: MissionPolicyEngine | None = None,
        impact: ImpactAnalysisEngine | None = None,
        cascade: FindingCascadeEngine | None = None,
    ) -> None:
        self.planning = planning
        self.hypothesis_loop = hypothesis_loop or HypothesisLoopEngine()
        self.decision = decision or MissionDecisionEngine()
        self.baseline = baseline or BaselineEngine()
        self.differential = differential or DifferentialTestEngine()
        self.negative = negative or NegativeEvidenceEngine()
        self.coverage = coverage or MissionCoverageEngine()
        self.gaps = gaps or KnowledgeGapEngine()
        self.confidence = confidence or ConfidenceEngine()
        self.branches = branches or BranchManager()
        self.telemetry = telemetry or MissionTelemetry()
        self.trace = trace or ReasoningTrace()
        self.policy = policy or MissionPolicyEngine()
        # Objective-aware completion contract: coverage-derived conditions only
        # become terminal when the contract confirms every mandatory dimension
        # was assessed (see hunterx.domain.mission_orchestration.completion).
        self.policy.completion_gate = self._completion_contract_gate
        self.impact = impact or ImpactAnalysisEngine()
        self.cascade = cascade or FindingCascadeEngine()
        self._missions: dict[str, OrchestratedMission] = {}

    # -- completion contract ---------------------------------------------------

    def _completion_contract_gate(self, mission: OrchestratedMission) -> tuple[bool, list[str]]:
        """Return ``(satisfied, unmet_gates)`` for the mission objective contract.

        ``pending_plan_work`` is derived from the planning graph (non-terminal
        actions still scheduled). An objective is complete only when its
        contract gates all pass — coverage alone never completes a full
        assessment.
        """
        from hunterx.domain.mission_orchestration.completion import contract_for_objective

        contract = contract_for_objective(
            getattr(getattr(mission, "mission", None), "objective", None),
            coverage_target=mission.policy.coverage_target,
        )
        assessment = contract.evaluate(mission, pending_plan_work=self._has_pending_plan_work(mission))
        return assessment.satisfied, assessment.unmet()

    # -- hypothesis classification ---------------------------------------------

    def defer_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        reason: str,
    ) -> dict[str, Any] | None:
        """Explicitly classify an open hypothesis as deferred with a reason.

        A deferred hypothesis is acknowledged but not tested now (capability
        unavailable, budget priority, out of scope). The recorded reason answers
        *why it remains open*. Deferral never implies the target is secure.
        """
        return self._classify_hypothesis(mission_id, hypothesis_id, HypothesisState.DEFERRED, reason)

    def block_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        reason: str,
    ) -> dict[str, Any] | None:
        """Explicitly classify an actionable hypothesis as blocked with a reason.

        A blocked hypothesis is actionable but cannot be probed under the
        current policy (capability unavailable / target not probeable). It is
        reported as blocked work, never as settled evidence.
        """
        return self._classify_hypothesis(mission_id, hypothesis_id, HypothesisState.BLOCKED, reason)

    def classify_open_hypotheses(
        self,
        mission_id: str,
        *,
        reason: str = "no runnable action under current policy/capability availability",
    ) -> int:
        """Classify non-actionable open hypotheses as DEFERRED (in place).

        Recon-derived facts (service/technology/endpoint hypotheses without a
        probeable vulnerability class and below high-priority) have no runnable
        test action; they are recorded as deferred with the given reason so the
        mission can reach an honest terminal (partial/blocked) instead of
        leaving a misleading count of "open" hypotheses that were never
        actionable.
        """
        mission = self.get(mission_id)
        classified = 0
        for hypothesis in list(mission.hypotheses):
            if hypothesis.state.value not in _OPEN_HYPOTHESIS_STATES:
                continue
            provenance = hypothesis.provenance or {}
            vulnerability_class = str(provenance.get("vulnerability_class") or "").strip()
            if hypothesis.priority >= 0.75 or vulnerability_class:
                # High-priority or vulnerability-class hypotheses are actionable:
                # they must be tested or explicitly blocked, never auto-deferred.
                continue
            self._classify_hypothesis(mission_id, hypothesis.hypothesis_id, HypothesisState.DEFERRED, reason)
            classified += 1
        return classified

    def _classify_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        state: HypothesisState,
        reason: str,
    ) -> dict[str, Any] | None:
        """Set an open hypothesis to ``state`` with a recorded reason (best-effort)."""
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            return None
        if hypothesis.state.value not in _OPEN_HYPOTHESIS_STATES:
            return hypothesis.to_dict()
        provenance = dict(hypothesis.provenance or {})
        provenance[f"{state.value}_reason"] = reason
        provenance[f"{state.value}_at"] = utcnow_iso()
        updated = replace(
            hypothesis,
            state=state,
            provenance=provenance,
            updated_at=utcnow_iso(),
        )
        mission.upsert_hypothesis(updated)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.RATIONALE,
            node_id=hypothesis_id,
            content={"event": f"hypothesis.{state.value}", "reason": reason},
        )
        return updated.to_dict()

    # -- target-model root asset -------------------------------------------------

    @staticmethod
    def _root_asset_entry(target: str) -> dict[str, Any]:
        """Return the canonical root-asset entry for ``target``."""
        from hunterx.shared.target import normalize_target

        spec = normalize_target(target)
        return {
            "key": target,
            "name": target,
            "host": spec.host_or_ip,
            "root": True,
            "kind": "url" if spec.scheme in ("http", "https") else "host",
            "content": {"target": target},
        }

    def _seed_root_asset(self, mission: OrchestratedMission) -> None:
        """Ensure the mission context holds a valid root asset for the target.

        A URL target (e.g. ``http://localhost:3010``) must produce a root asset
        entity before any downstream services/endpoints/technologies are
        attached — otherwise the target model is an orphaned set of children.
        Idempotent: the root is seeded once.
        """
        target = mission.context.target_id or ""
        if not target:
            return
        key = f"asset:{target}"
        if key in mission.context.assets:
            return
        mission.context.assets[key] = self._root_asset_entry(target)

    # -- mission lifecycle --------------------------------------------------

    def create_mission(
        self,
        *,
        objective: MissionObjective | str = "full_security_assessment",
        mode: MissionMode | str = MissionMode.BALANCED,
        target: str = "",
        scope: MissionScope | None = None,
        policy: MissionPolicy | None = None,
        strategy: StrategyKind = StrategyKind.ADAPTIVE,
        tenant: str = "",
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
    ) -> OrchestratedMission:
        """Create an orchestrated mission over an adaptive planning mission."""
        from hunterx.domain.mission_orchestration.objective import resolve_objective

        objective_enum = (
            objective
            if isinstance(objective, MissionObjective)
            else resolve_objective(objective)
        )
        mode_enum = mode if isinstance(mode, MissionMode) else MissionMode(mode)
        adaptive = (
            self.planning.create_mission(
                objective=objective_enum,
                mode=mode_enum,
                authorization_context=authorization_context,
                safety_ceiling=safety_ceiling,
                tenant=tenant,
                target=target,
            )
            if self.planning is not None
            else AdaptiveMission(objective=objective_enum, mode=mode_enum)
        )
        objective_name = objective if isinstance(objective, str) else objective.value
        strategy_enum = strategy if isinstance(strategy, StrategyKind) else StrategyKind(strategy)
        effective_scope = scope or MissionScope(
            included_targets=(target,) if target else (),
            authorization_contexts=(authorization_context,),
        )
        effective_policy = policy or MissionPolicy(
            objective_name=objective_name,
            strategy=strategy_enum,
            allowed_techniques=(),
        )
        mission = new_orchestrated_mission(
            mission=adaptive,
            scope=effective_scope,
            policy=effective_policy,
            target_id=target,
        )
        mission.context.current_objectives = _objectives_for(objective_enum)
        mission.context.remaining_objectives = list(mission.context.current_objectives)
        self._seed_root_asset(mission)
        self._missions[mission.mission_id] = mission
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.RATIONALE,
            node_id=mission.mission_id,
            content={"event": "mission.created", "objective": objective_enum.value},
        )
        return mission

    def get(self, mission_id: str) -> OrchestratedMission:
        """Return an orchestrated mission by id."""
        mission = self._missions.get(mission_id)
        if mission is None:
            from hunterx.domain.exceptions.adaptive_mission_planning import AdaptiveMissionNotFoundError

            raise AdaptiveMissionNotFoundError(mission_id)
        return mission

    def restore(self, mission: OrchestratedMission) -> OrchestratedMission:
        """Register an already-persisted mission back into the in-memory store.

        This is the restart path: the application service hydrates an
        ``OrchestratedMission`` from the TIDB system-of-record and registers it
        here so ``start``/``pause``/``resume``/``cancel`` work across process
        restarts and CLI invocations. The underlying adaptive aggregate is also
        re-registered with the adaptive planning engine.
        """
        self._missions[mission.mission_id] = mission
        if self.planning is not None:
            restore = getattr(self.planning, "restore", None)
            if callable(restore):
                restore(mission.mission)
        return mission

    def missions(self) -> list[OrchestratedMission]:
        """Return all registered orchestrated missions."""
        return list(self._missions.values())

    def start(self, mission_id: str) -> OrchestratedMission:
        """Start (or resume) a mission run."""
        mission = self.get(mission_id)
        if self.planning is not None:
            self.planning.transition(mission.mission_id, MissionState.DISCOVERY)
        run = MissionRun(
            run_id=generate_id(),
            mission_id=mission_id,
            status=MissionRunStatus.RUNNING,
            started_at=utcnow_iso(),
        )
        mission.runs.append(run)
        mission.context.history.append({"event": MissionEventType.MISSION_STARTED.value, "run_id": run.run_id})
        self._trace_mission(mission, MissionEventType.MISSION_STARTED, run_id=run.run_id)
        return mission

    def pause(self, mission_id: str) -> OrchestratedMission:
        """Pause a mission."""
        mission = self.get(mission_id)
        if self.planning is not None:
            self.planning.pause(mission_id)
        if mission.runs:
            mission.runs[-1].status = MissionRunStatus.PAUSED
        return mission

    def resume(self, mission_id: str) -> OrchestratedMission:
        """Resume a paused mission."""
        mission = self.get(mission_id)
        if self.planning is not None:
            self.planning.resume(mission_id)
        if mission.runs:
            mission.runs[-1].status = MissionRunStatus.RESUMED
        return mission

    def cancel(self, mission_id: str) -> OrchestratedMission:
        """Cancel a mission."""
        mission = self.get(mission_id)
        if self.planning is not None:
            self.planning.cancel(mission_id)
        if mission.runs:
            mission.runs[-1].status = MissionRunStatus.CANCELLED
            mission.runs[-1].finished_at = utcnow_iso()
        mission.current_phase = MissionPhase.REPORTING
        mission.outcome = MissionOutcome(
            mission_id=mission_id,
            phase=mission.current_phase.value,
            stop_condition=StopCondition.OPERATOR_CANCELLED.value,
        )
        self._trace_mission(mission, MissionEventType.MISSION_COMPLETED, stop="cancelled")
        return mission

    def finalize(self, mission_id: str, *, stop_condition: StopCondition | None = None) -> OrchestratedMission:
        """Finalize a mission and record its outcome.

        Idempotent: an already-finalized mission (outcome recorded) is
        returned unchanged, so every terminal runner exit path may call this
        safely.

        Termination is truthful: the stop condition is the genuinely fired one
        (explicit or policy-evaluated). When nothing fired and the objectives
        are NOT complete, the mission is reported as ``BLOCKED`` (no actionable
        work / exhausted) — it is never silently converted into success.

        Open non-actionable hypotheses (recon facts with no runnable test) are
        first recorded as ``DEFERRED`` with an explicit reason so the aggregate
        distinguishes "assessed and deferred" from "untested actionable work".
        The planning state walks to COMPLETED only when the objectives are
        genuinely complete; an incomplete mission walks to BLOCKED instead —
        ``planning_state=completed`` never implies execution was complete.
        """
        mission = self.get(mission_id)
        if mission.outcome is not None:
            return mission
        self.classify_open_hypotheses(mission_id)
        explicit = stop_condition
        evaluated = self.policy.evaluate_stop(mission) if explicit is None else None
        condition = explicit or evaluated
        objectives_complete = self._objectives_satisfied(mission)
        if condition is None:
            if objectives_complete:
                condition = StopCondition.OBJECTIVES_COMPLETE
            elif mission.budget.exhausted:
                condition = StopCondition.RESOURCE_BUDGET_EXHAUSTED
            elif self._blocked_unresolved(mission):
                condition = StopCondition.BLOCKED
            else:
                condition = StopCondition.BLOCKED
        elif condition in _SUCCESS_STOP_CONDITIONS:
            objectives_complete = True
        # INVARIANT A/B: RESOURCE_BUDGET_EXHAUSTED / TIME_BUDGET_EXHAUSTED may
        # ONLY be emitted when the corresponding real resource predicate is
        # true. A resource stop supplied explicitly while no resource is
        # actually exhausted is a semantic lie (the real regression: 16/1000
        # executions with 984 remaining reported as resource exhaustion) — it
        # is downgraded to an honest blocked/no-actionable terminal.
        if (
            condition is StopCondition.RESOURCE_BUDGET_EXHAUSTED and not mission.budget.exhausted
        ) or (
            condition is StopCondition.TIME_BUDGET_EXHAUSTED and not mission.budget.time_exhausted
        ):
            condition = StopCondition.NO_ACTIONABLE_WORK
        if condition in (StopCondition.BLOCKED, StopCondition.NO_ACTIONABLE_WORK, StopCondition.AI_UNAVAILABLE):
            objectives_complete = False
        if self.planning is not None:
            if objectives_complete:
                self._advance_to_completed(mission_id)
            else:
                self._advance_to_blocked(mission_id)
        if objectives_complete:
            mission.current_phase = MissionPhase.REPORTING
        else:
            # A blocked/incomplete mission is never reported in the reporting
            # phase; the phase reflects the (final) planning state, so a
            # blocked mission is honestly shown as reassessment rather than a
            # stale reconnaissance.
            if self.planning is not None:
                mission.current_phase = self.sync_phase(mission_id)
            if mission.current_phase in (MissionPhase.REPORTING,):
                mission.current_phase = MissionPhase.REASSESSMENT
        if mission.runs:
            mission.runs[-1].status = MissionRunStatus.COMPLETED
            mission.runs[-1].finished_at = utcnow_iso()
        validated = sum(
            1
            for finding in mission.context.findings
            if finding.get("stage") in ("verified", "proven", "report_ready")
        )
        report_ready = sum(1 for finding in mission.context.findings if finding.get("stage") == "report_ready")
        resolved = sum(
            1 for hypothesis in mission.hypotheses if hypothesis.state.is_terminal
        )
        deferred = sum(
            1 for hypothesis in mission.hypotheses if hypothesis.state.is_classified
        )
        mission.outcome = MissionOutcome(
            mission_id=mission_id,
            phase=mission.current_phase.value,
            objectives_complete=objectives_complete,
            findings_validated=validated,
            findings_report_ready=report_ready,
            hypotheses_resolved=resolved,
            hypotheses_deferred=deferred,
            hypotheses_open=sum(
                1 for hypothesis in mission.hypotheses if hypothesis.state.value in _OPEN_HYPOTHESIS_STATES
            ),
            probes_executed=sum(
                1
                for observation in mission.observations
                if observation.observation_type == "probe"
            ),
            attack_paths_discovered=len(mission.context.attack_paths),
            coverage_ratio=mission.coverage_ratio(),
            executions_used=mission.budget.executions_used,
            stop_condition=condition.value,
            exhausted_resource=mission.budget.exhausted_resource() if condition in (StopCondition.RESOURCE_BUDGET_EXHAUSTED, StopCondition.TIME_BUDGET_EXHAUSTED) else "",
            ai_unavailable=_ai_unavailable(mission),
            blocked_reason=self._blocked_reason(mission, condition),
        )
        self.telemetry.record(mission)
        self._trace_mission(mission, MissionEventType.MISSION_COMPLETED, stop_condition=condition.value)
        return mission

    @staticmethod
    def _blocked_reason(mission: OrchestratedMission, condition: StopCondition) -> str:
        """Return an explicit, explainable blocking reason for a non-success terminal.

        INVARIANT F: ``planning_state=blocked`` must be accompanied by a
        truthful reason distinguishing resource exhaustion, no actionable work,
        AI unavailability, open-but-undischarged hypotheses, and completion-gate
        failure.
        """
        if condition is StopCondition.RESOURCE_BUDGET_EXHAUSTED:
            return f"resource_budget_exhausted:{mission.budget.exhausted_resource()}"
        if condition is StopCondition.TIME_BUDGET_EXHAUSTED:
            return "time_budget_exhausted"
        if condition is StopCondition.CYCLE_CEILING_REACHED:
            return "cycle_ceiling_reached: operational cycle limit reached with budget remaining"
        if condition is StopCondition.AI_UNAVAILABLE:
            return "ai_unavailable: model unavailable/rate-limited and no deterministic work remains"
        if condition is StopCondition.NO_ACTIONABLE_WORK:
            unmet = _completion_gate_unmet(mission)
            if unmet:
                return f"no_actionable_work: completion contract unmet ({', '.join(unmet)})"
            return "no_actionable_work: planner has no runnable action and the objective contract is unmet"
        if condition is StopCondition.BLOCKED:
            if MissionPolicyEngine._has_open_high_value_hypotheses(mission):
                return "blocked: open actionable hypotheses could not be discharged (capability unavailable / target not probeable)"
            unmet = _completion_gate_unmet(mission)
            if unmet:
                return f"blocked: completion contract unmet ({', '.join(unmet)})"
            return "blocked: no actionable work and the objective contract is unmet"
        return ""

    def _advance_to_blocked(self, mission_id: str) -> None:
        """Walk the planning state machine to BLOCKED through legal hops.

        An incomplete mission (blocked / budget-exhausted / no actionable work)
        must not be reported as ``planning_state=completed``: ``completed``
        implies the objective contract was satisfied. BLOCKED is reachable from
        every active state; REPORTING (already in the completion corridor) is
        left untouched and the outcome records the honest blocked terminal.
        """
        if self.planning is None:
            return
        from hunterx.domain.adaptive_mission_planning.enums import MissionState

        current = self.planning.get_mission(mission_id).state
        if current in (MissionState.BLOCKED, MissionState.COMPLETED, MissionState.CANCELLED, MissionState.FAILED):
            return
        from hunterx.domain.adaptive_mission_planning.state import can_transition

        if can_transition(current, MissionState.BLOCKED):
            self.planning.transition(mission_id, MissionState.BLOCKED)
            return
        if current is MissionState.REPORTING:
            # REPORTING cannot legally re-enter BLOCKED; the outcome records the
            # blocked terminal and the phase reflects reassessment.
            return
        if can_transition(current, MissionState.REASSESSMENT):
            with contextlib.suppress(Exception):  # best-effort legal hop
                self.planning.transition(mission_id, MissionState.REASSESSMENT)
                self.planning.transition(mission_id, MissionState.BLOCKED)

    # -- observation intake --------------------------------------------------

    def record_attack_paths(self, mission_id: str) -> list[dict[str, Any]]:
        """Record attack paths from the discovered attack-surface context.

        Attack paths are intelligence only — they never trigger execution. The
        surface graph is derived from the mission context (host → port/service
        → endpoint) and the planning engine's attack-path engine discovers the
        exposure→application chains. Paths are stored on the mission context
        (for dashboards/reports) and on the adaptive mission aggregate, and
        validation state is fed from the mission's findings.
        """
        mission = self.get(mission_id)
        if self.planning is None:
            return list(mission.context.attack_paths)
        from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph, relationship_for
        from hunterx.domain.target_intelligence.models import IntelligenceAsset
        from hunterx.domain.topology.enums import EntityKind, RelationshipType
        from hunterx.shared.target import normalize_target

        graph = AttackSurfaceGraph()
        target_id = mission.context.target_id or ""
        target_spec = normalize_target(target_id)
        host = target_spec.host_or_ip
        host_asset = None
        if host:
            host_kind = EntityKind.HOSTNAME if ("." in host and not _is_ipv4(host)) else EntityKind.IP
            host_asset = IntelligenceAsset(
                kind=host_kind,
                name=host,
                key=f"{host_kind.value}:{host}",
                label=f"host {host}",
                in_scope=True,
            )
            graph.upsert_asset(host_asset)

        port = target_spec.port or (443 if target_spec.scheme == "https" else 80)
        port_asset = IntelligenceAsset(
            kind=EntityKind.PORT,
            name=str(port),
            key=f"port:{host}:{port}" if host else f"port:{port}",
            label=f"port {port}",
            in_scope=True,
            properties={"protocol": target_spec.scheme or "http"},
        )
        graph.upsert_asset(port_asset)
        if host_asset is not None:
            graph.add_relationship(
                relationship_for(
                    RelationshipType.CONTAINS,
                    host_asset,
                    port_asset,
                    mission_id=mission_id,
                    source_name="mission-context",
                    confidence=0.8,
                )
            )

        service_assets: dict[str, IntelligenceAsset] = {}
        for entry in list(mission.context.services.values())[:_MAX_ATTACK_PATH_SERVICES]:
            identity = str(entry.get("identity") or entry.get("key") or "")
            if not identity:
                continue
            service_asset = IntelligenceAsset(
                kind=EntityKind.SERVICE,
                name=identity,
                key=f"service:{identity}",
                label=f"service {identity}",
                in_scope=True,
            )
            graph.upsert_asset(service_asset)
            service_assets[identity] = service_asset
            graph.add_relationship(
                relationship_for(
                    RelationshipType.SERVES,
                    port_asset,
                    service_asset,
                    mission_id=mission_id,
                    source_name="mission-context",
                    confidence=0.7,
                )
            )

        validated_map = {
            str(finding.get("asset_key")): finding.get("stage") in ("verified", "proven", "report_ready")
            for finding in mission.context.findings
        }
        for _key, entry in list(mission.context.endpoints.items())[:_MAX_ATTACK_PATH_ENDPOINTS]:
            url = str(entry.get("key") or entry.get("url") or "")
            if not url:
                continue
            parameters = [
                str(param.get("parameter"))
                for param_key, param in mission.context.parameters.items()
                if isinstance(param, dict) and str(param.get("key") or "") == url and param.get("parameter")
            ]
            endpoint_asset = IntelligenceAsset(
                kind=EntityKind.URL,
                name=url,
                key=f"url:{url}",
                label=f"endpoint {url}",
                in_scope=True,
                properties={"parameters": [p for p in parameters if p]},
            )
            graph.upsert_asset(endpoint_asset)
            graph.add_relationship(
                relationship_for(
                    RelationshipType.SERVES,
                    port_asset,
                    endpoint_asset,
                    mission_id=mission_id,
                    source_name="mission-context",
                    confidence=0.8,
                )
            )
            for service_asset in service_assets.values():
                graph.add_relationship(
                    relationship_for(
                        RelationshipType.SERVES,
                        service_asset,
                        endpoint_asset,
                        mission_id=mission_id,
                        source_name="mission-context",
                        confidence=0.7,
                    )
                )

        evidence_map: dict[str, tuple[str, ...]] = {}
        for observation in mission.observations:
            asset_key = observation.asset_key or ""
            if not asset_key:
                continue
            refs = evidence_map.setdefault(asset_key, ())
            if observation.observation_id not in refs:
                evidence_map[asset_key] = (*refs, observation.observation_id)
        # Hypotheses whose provenance names an asset also count as evidence so a
        # hypothesis-derived chain is SUPPORTED, never a bare graph permutation.
        for hypothesis in mission.hypotheses:
            asset_key = str((hypothesis.provenance or {}).get("asset_key") or "")
            if not asset_key:
                continue
            refs = evidence_map.setdefault(asset_key, ())
            if hypothesis.hypothesis_id not in refs:
                evidence_map[asset_key] = (*refs, hypothesis.hypothesis_id)
        paths = self.planning.discover_attack_paths(
            mission.mission_id,
            surface=graph,
            evidence_map=evidence_map,
            validated_map=validated_map,
        )
        mission.mission.attack_paths = paths
        # Attack-path semantics (Phase 11): only evidence-supported paths are
        # reported as discovered attack paths. Purely structural adjacency
        # chains (port→service, service→URL, ...) are recorded as surface
        # relationships — never labelled as discovered attacks.
        from hunterx.domain.adaptive_mission_planning.enums import AttackPathState

        supported = [path for path in paths if path.state in (AttackPathState.SUPPORTED, AttackPathState.VALIDATED, AttackPathState.PROVED)]
        structural = [path for path in paths if path.state is AttackPathState.HYPOTHETICAL]
        mission.context.attack_paths = [path.to_dict() for path in supported]
        mission.context.surface_relationships = [path.to_dict() for path in structural]
        return list(mission.context.attack_paths)

    def record_probe(
        self,
        mission_id: str,
        *,
        vulnerability_class: str,
        endpoint: str = "",
        parameter: str = "",
        action_id: str = "",
        signal: str = "",
        supported: bool = False,
        contradicted: bool = False,
        notes: str = "",
        payload_count: int = 0,
        response_summary: dict[str, Any] | None = None,
        evidence_ref: str = "",
    ) -> MissionObservation:
        """Record a targeted differential probe execution as a first-class observation.

        A probe observation proves that a targeted probe ran and what it
        observed (baseline vs. payload response summary and verdict). It is
        advisory evidence for the hypothesis loop — it is NOT vulnerability
        evidence. Vulnerability evidence is persisted only when the probe
        verdict supports the class and flows into the finding record
        (e.g. ``BEHAVIORAL_DIFFERENTIAL``), so
        ``targeted probe >= 1`` never by itself implies ``evidence >= 1``.
        """
        mission = self.get(mission_id)
        observation = MissionObservation(
            observation_id=generate_id(),
            mission_id=mission_id,
            action_id=action_id,
            tool_id="hunterx-capability",
            asset_key=endpoint or mission.context.target_id,
            observation_type="probe",
            content={
                "vulnerability_class": vulnerability_class,
                "endpoint": endpoint,
                "parameter": parameter,
                "signal": signal,
                "supported": supported,
                "contradicted": contradicted,
                "notes": notes,
                "payload_count": payload_count,
                "response_summary": response_summary or {},
            },
            evidence_ref=evidence_ref,
            confidence=1.0 if supported else 0.0,
            raw_tool_id="hunterx-capability",
            provenance={"probe": True, "vulnerability_class": vulnerability_class},
        )
        mission.add_observation(observation)
        mission.context.tool_executions.append(
            {
                "action_id": action_id,
                "tool_id": "hunterx-capability",
                "tool_version": "",
                "asset_key": endpoint or mission.context.target_id,
                "capability": vulnerability_class,
                "probe": True,
                "supported": supported,
                "executed_at": utcnow_iso(),
            }
        )
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.OBSERVATION,
            node_id=observation.observation_id,
            content={"type": "probe", "vulnerability_class": vulnerability_class, "supported": supported},
        )
        return observation

    def ingest_result(
        self,
        mission_id: str,
        *,
        tool_id: str,
        tool_version: str = "",
        action_id: str = "",
        asset_key: str = "",
        raw: dict[str, Any],
    ) -> MissionObservation:
        """Parse and normalize a tool result into a mission observation.

        This is the entry point of the adaptive loop: the orchestrator treats
        the raw output as data — never as an instruction.
        """
        mission = self.get(mission_id)
        observation = MissionObservation(
            observation_id=generate_id(),
            mission_id=mission_id,
            action_id=action_id,
            tool_id=tool_id,
            tool_version=tool_version,
            asset_key=asset_key,
            observation_type=str(raw.get("observation_type", "asset")),
            content=_normalize_content(raw.get("content", raw)),
            evidence_ref=str(raw.get("evidence_ref", "")),
            confidence=float(raw.get("confidence", 0.5)),
            raw_tool_id=tool_id,
            provenance={"tool_id": tool_id, "tool_version": tool_version, "action_id": action_id},
        )
        mission.add_observation(observation)
        self._populate_context(mission, observation)
        self._hypothesize_from_observation(mission, observation)
        self._hypothesize_from_context(mission)
        self._link_findings_to_hypotheses(mission, observation)
        mission.budget.executions_used += 1
        mission.budget.time_used_seconds = _elapsed_seconds(mission)
        mission.context.tool_executions.append(
            {
                "action_id": action_id,
                "tool_id": tool_id,
                "tool_version": tool_version,
                "asset_key": asset_key,
                "executed_at": utcnow_iso(),
            }
        )
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.OBSERVATION,
            node_id=observation.observation_id,
            content={"tool": tool_id, "asset": asset_key, "type": observation.observation_type},
        )
        self._trace_mission(mission, MissionEventType.MISSION_OBSERVATION_CREATED, observation_id=observation.observation_id)
        return observation

    def _link_findings_to_hypotheses(self, mission: OrchestratedMission, observation: MissionObservation) -> None:
        """Attach the hypothesis that explains each candidate finding.

        The candidate finding and the hypothesis are both derived from the same
        observation; recording ``hypothesis_id`` on the finding lets the runner
        promote the finding only when ITS explaining hypothesis is validated.
        Linking is by vulnerability class (and endpoint), so one observation
        with many classes never lets a single validated hypothesis promote
        findings of other classes.
        """
        observation_id = observation.observation_id
        class_hypotheses: dict[tuple[str, str], str] = {}
        for hypothesis in mission.hypotheses:
            if observation_id and observation_id not in hypothesis.supporting_evidence:
                continue
            provenance = hypothesis.provenance or {}
            class_id = str(provenance.get("vulnerability_class") or "")
            endpoint = str(provenance.get("endpoint") or "")
            if class_id:
                class_hypotheses[(class_id, endpoint)] = hypothesis.hypothesis_id
        for finding in mission.context.findings:
            if finding.get("stage") != "candidate":
                continue
            refs = finding.get("evidence_refs") or ()
            if observation_id not in refs:
                continue
            if finding.get("hypothesis_id") in (None, ""):
                class_id = str(finding.get("vulnerability_class") or "")
                endpoint = str(finding.get("asset_key") or "")
                finding["hypothesis_id"] = class_hypotheses.get((class_id, endpoint)) or class_hypotheses.get((class_id, ""))

    def record_negative(
        self,
        mission_id: str,
        *,
        asset_key: str,
        capability: str,
        kind: str = "tested",
        tool_id: str = "",
        tool_version: str = "",
        input: Any = None,
        outcome: str = "",
        notes: str = "",
    ) -> NegativeEvidenceRecord:
        """Record bounded negative evidence on the mission."""
        mission = self.get(mission_id)
        record = self.negative.record(
            mission_id=mission_id,
            asset_key=asset_key,
            capability=capability,
            kind=kind,
            tool_id=tool_id,
            tool_version=tool_version,
            input=input,
            outcome=outcome,
            notes=notes,
        )
        if record not in mission.negative_evidence:
            mission.negative_evidence.append(record)
        return record

    # -- phase synchronization ---------------------------------------------

    def sync_phase(self, mission_id: str) -> MissionPhase:
        """Synchronize the orchestration phase from the planning state.

        The canonical ``MissionPhase`` mirrors the Sprint 027 ``MissionState``
        progression; the orchestration phase is derived from the meaningful
        workflow state — never from the number of tools that ran.
        """
        mission = self.get(mission_id)
        if self.planning is None:
            return mission.current_phase
        state = self.planning.get_mission(mission_id).state
        mapped = _PHASE_BY_PLANNING_STATE.get(state)
        if mapped is None:
            return mission.current_phase
        mission.current_phase = mapped
        return mapped

    # -- hypothesis loop -----------------------------------------------------

    def add_hypothesis(
        self,
        mission_id: str,
        *,
        statement: str,
        category: HypothesisType | str = HypothesisType.UNKNOWN_BEHAVIOR,
        supporting: tuple[str, ...] = (),
        confidence: float = 0.4,
        priority: float = 0.5,
        validation_strategy: str = "",
        proof_strategy: str = "",
        behavior_class: BehaviorClass = BehaviorClass.NOVEL_CANDIDATE,
        proposed_by: str = "orchestrator",
        provenance_hint: dict[str, Any] | None = None,
    ) -> MissionHypothesis:
        """Create and register a hypothesis (idempotent by statement)."""
        mission = self.get(mission_id)
        for existing in mission.hypotheses:
            if existing.statement == statement:
                # The hypothesis already exists: merge the new supporting
                # evidence so independent observations accumulate on one
                # hypothesis (drives SUPPORTED → VALIDATED), instead of a fresh
                # duplicate per observation.
                merged_supporting = tuple(dict.fromkeys(existing.supporting_evidence + tuple(supporting)))
                if merged_supporting and merged_supporting != existing.supporting_evidence:
                    merged = replace(existing, supporting_evidence=merged_supporting, updated_at=utcnow_iso())
                    mission.upsert_hypothesis(merged)
                    return merged
                return existing
        category_enum = _coerce_category(category)
        provenance = {"created_by": proposed_by, **(provenance_hint or {})}
        hypothesis = self.hypothesis_loop.hypothesize(
            mission_id=mission_id,
            statement=statement,
            category=category_enum,
            supporting=supporting,
            confidence=confidence,
            priority=priority,
            validation_strategy=validation_strategy,
            proof_strategy=proof_strategy,
            behavior_class=behavior_class,
            proposed_by=proposed_by,
        )
        hypothesis = replace(hypothesis, provenance=provenance)
        mission.upsert_hypothesis(hypothesis)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.HYPOTHESIS,
            node_id=hypothesis.hypothesis_id,
            content={"statement": statement, "category": str(category)},
        )
        self._trace_mission(mission, MissionEventType.MISSION_HYPOTHESIS_CREATED, hypothesis_id=hypothesis.hypothesis_id)
        return hypothesis

    def update_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        supporting: tuple[str, ...] = (),
        contradicting: tuple[str, ...] = (),
        tested_action: str = "",
    ) -> MissionHypothesis:
        """Advance a hypothesis with new evidence through the hypothesis loop."""
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            raise KeyError(hypothesis_id)
        updated = self.hypothesis_loop.update(
            hypothesis,
            supporting=supporting,
            contradicting=contradicting,
            tested_action=tested_action,
        )
        mission.upsert_hypothesis(updated)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.HYPOTHESIS,
            node_id=hypothesis_id,
            content={"state": updated.state.value, "supporting": len(updated.supporting_evidence)},
            parent_entry_id=self._last_entry_id(mission),
        )
        self._trace_mission(mission, MissionEventType.MISSION_HYPOTHESIS_UPDATED, hypothesis_id=hypothesis_id, state=updated.state.value)
        return updated
    def verify_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        reproducible: bool = True,
    ) -> MissionHypothesis:
        """Promote a supported hypothesis to VALIDATED after independent verification."""
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            raise KeyError(hypothesis_id)
        updated = self.hypothesis_loop.verify(hypothesis, reproducible=reproducible)
        mission.upsert_hypothesis(updated)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.HYPOTHESIS,
            node_id=hypothesis_id,
            content={"state": updated.state.value, "verification": "independent"},
        )
        self._trace_mission(mission, MissionEventType.MISSION_HYPOTHESIS_UPDATED, hypothesis_id=hypothesis_id, state=updated.state.value)
        return updated

    def refute_hypothesis(
        self,
        mission_id: str,
        hypothesis_id: str,
        *,
        reason: str = "",
        tested_action: str = "",
    ) -> MissionHypothesis:
        """Refute a hypothesis whose class-specific probe found no signal.

        A contradicted differential verdict means the specific weakness class
        was not observed — the hypothesis is REFUTED (honest negative), never
        silently dropped and never validated. The candidate finding stays
        candidate.
        """
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            raise KeyError(hypothesis_id)
        tested_actions = tuple(dict.fromkeys(hypothesis.tested_actions + ((tested_action,) if tested_action else ())))
        updated = replace(
            hypothesis,
            state=HypothesisState.REFUTED,
            tested_actions=tested_actions,
            updated_at=utcnow_iso(),
            provenance={**hypothesis.provenance, "refuted_by_probe": reason or "no class-specific signal"},
        )
        mission.upsert_hypothesis(updated)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.HYPOTHESIS,
            node_id=hypothesis_id,
            content={"state": updated.state.value, "reason": reason},
        )
        self._trace_mission(mission, MissionEventType.MISSION_HYPOTHESIS_UPDATED, hypothesis_id=hypothesis_id, state=updated.state.value)
        return updated

    def start_novel(self, mission_id: str, *, asset_key: str, behavior_summary: str) -> NovelBehaviorRecord:
        """Open a novel-behavior investigation record."""
        mission = self.get(mission_id)
        record = self.hypothesis_loop.start_novel(
            mission_id=mission_id,
            asset_key=asset_key,
            behavior_summary=behavior_summary,
        )
        mission.novel_behaviors.append(record)
        return record

    def advance_novel(
        self,
        mission_id: str,
        record_id: str,
        *,
        stage: NovelPipelineStage | None = None,
        experiments: tuple[str, ...] = (),
        observations: tuple[str, ...] = (),
        proof_ref: str = "",
    ) -> NovelBehaviorRecord:
        """Advance a novel-behavior record through the experiment loop."""
        mission = self.get(mission_id)
        for index, record in enumerate(mission.novel_behaviors):
            if record.record_id == record_id:
                updated = self.hypothesis_loop.advance_novel(
                    record,
                    stage=stage,
                    experiments=experiments,
                    observations=observations,
                    proof_ref=proof_ref,
                )
                mission.novel_behaviors[index] = updated
                return updated
        raise KeyError(record_id)

    # -- decision loop -------------------------------------------------------

    def decide_next(
        self,
        mission_id: str,
        *,
        candidates: tuple[CandidateAction, ...] | list[Any] = (),
        ai_suggestion: str = "",
        ai_reason: str = "",
    ) -> MissionDecision | None:
        """Rank candidate actions and select the next one (explained)."""
        mission = self.get(mission_id)
        effective = tuple(_coerce_candidate(candidate) for candidate in candidates) or self._candidates_from_plan(mission)
        if not effective:
            return None
        inp = DecisionInput(
            mission_id=mission_id,
            candidates=effective,
            hypotheses=tuple(mission.open_hypotheses()),
            negative_evidence=tuple(mission.negative_evidence),
            coverage_ratio=mission.coverage_ratio(),
            strategy=mission.policy.strategy,
            ai_suggestion=ai_suggestion,
            ai_reason=ai_reason,
        )
        decision = self.decision.decide(inp)
        if decision is not None:
            mission.add_decision(decision)
            self._record_trace(
                mission,
                kind=ReasoningTraceKind.DECISION,
                node_id=decision.decision_id,
                content={"next_action": decision.next_action, "priority": decision.priority, "reason": decision.reason},
            )
            self._trace_mission(
                mission,
                MissionEventType.MISSION_ACTION_SELECTED,
                action_id=decision.next_action,
                tool_id=decision.tool_id,
            )
        return decision

    def record_ai_decision(
        self,
        mission_id: str,
        *,
        decision_id: str = "",
        capability: str = "",
        tool_id: str = "",
        action_id: str = "",
        reason: str = "",
        expected_result: str = "",
        priority: float = 0.7,
        latency_ms: int = 0,
        provider: str = "",
        model: str = "",
        security_domain: str = "",
    ) -> MissionDecision:
        """Persist an AI Hunt Director decision as a first-class record.

        AI-directed actions never pass through the deterministic ranking, so
        without this record the durable decision log would show only
        deterministic decisions and understate AI involvement. The record is
        marked ``ai_assisted`` and carries provider/model provenance (never
        credentials) in its factors.
        """
        mission = self.get(mission_id)
        decision = MissionDecision(
            decision_id=decision_id or generate_id(),
            mission_id=mission_id,
            next_action=action_id,
            capability=capability,
            tool_id=tool_id,
            reason=reason[:500],
            expected_result=expected_result[:300],
            priority=priority,
            factors={
                "ai_provider": provider,
                "ai_model": model,
                "security_domain": security_domain,
                "decision_source": "ai_hunt_director",
            },
            ai_assisted=True,
            latency_ms=latency_ms,
        )
        mission.add_decision(decision)
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.DECISION,
            node_id=decision.decision_id,
            content={
                "source": "ai_hunt_director",
                "provider": provider,
                "model": model,
                "capability": capability,
                "tool_id": tool_id,
                "security_domain": security_domain,
                "reason": reason[:300],
            },
        )
        return decision

    def _candidates_from_plan(self, mission: OrchestratedMission) -> tuple[CandidateAction, ...]:
        """Build candidate actions from the adaptive mission's ready actions.

        An action explicitly bound to an open hypothesis (the replanning layer
        links a NEW_HYPOTHESIS_CREATED validation node to its hypothesis) is
        marked with ``hypothesis_id`` so the decision engine can rank evidence-
        driven probes above unrelated work.

        Replay protection: a ready action whose identity was already executed
        (a materially identical action completed earlier with no new state) is
        invalidated — its repeated branch is dropped (``SUPERSEDED``) — so the
        planner selects another actionable branch instead of blindly re-running
        the same tool against the same input.
        """
        if self.planning is None:
            return ()
        graph = self.planning.get_plan(mission.mission_id)
        ready = self.planning.next_parallel_wave(mission.mission_id)
        candidates: list[CandidateAction] = []
        for action in ready:
            if graph.completed_identical(action):
                # Same capability + asset + hypothesis + parameter/technology +
                # tool was already completed: this is a stale repeated branch.
                action.mark(ActionStatus.SUPERSEDED)
                continue
            linked = ""
            if action.hypothesis_id and mission.hypothesis(action.hypothesis_id) is not None:
                linked = action.hypothesis_id
            candidates.append(
                CandidateAction(
                    action_id=action.action_id,
                    capability=action.capability,
                    description=action.action_type.value,
                    tool_ids=(action.selected_tool,) if action.selected_tool else tuple(action.tool_candidate_set),
                    expected_information_gain=action.expected_information_gain,
                    attack_surface_expansion=0.3,
                    finding_validation_potential=0.2 if "validate" in action.action_type.value else 0.1,
                    evidence_improvement=0.3,
                    hypothesis_discrimination=0.2 if linked else 0.1,
                    coverage_improvement=0.3,
                    cost=action.cost,
                    dependencies=action.depends_on,
                    reliability=max(0.5, 1.0 - action.risk),
                    hypothesis_id=linked,
                )
            )
        return tuple(candidates)

    # -- policy gate ---------------------------------------------------------

    def check_action(self, mission_id: str, *, capability: str, target: str, technique: str = "") -> PolicyVerdict:
        """Evaluate the policy gates for an action."""
        mission = self.get(mission_id)
        return self.policy.check_action(mission, capability=capability, target=target, technique=technique)

    def stop_condition(self, mission_id: str) -> StopCondition | None:
        """Evaluate the mission stop conditions."""
        return self.policy.evaluate_stop(self.get(mission_id))

    # -- coverage / gaps -----------------------------------------------------

    def record_coverage(
        self,
        mission_id: str,
        *,
        asset_key: str,
        capability: CoverageCapability | str,
        state: CoverageState | str,
        tool_id: str = "",
        confidence: float = 0.0,
        evidence_refs: tuple[str, ...] = (),
        notes: str = "",
    ) -> None:
        """Record a coverage cell."""
        self.coverage.record(
            self.get(mission_id),
            asset_key=asset_key,
            capability=capability,
            state=state,
            tool_id=tool_id,
            confidence=confidence,
            evidence_refs=evidence_refs,
            notes=notes,
        )

    def knowledge_gaps(self, mission_id: str) -> list[KnowledgeGap]:
        """Return ranked knowledge gaps for a mission."""
        return self.gaps.analyze(self.get(mission_id))

    def coverage_summary(self, mission_id: str) -> dict[str, Any]:
        """Return the mission coverage summary."""
        return self.coverage.summary(self.get(mission_id))

    # -- baseline / differential ---------------------------------------------

    def capture_baseline(
        self,
        mission_id: str,
        *,
        asset_key: str,
        request_fingerprint: str = "",
        status_code: int = 0,
        headers: Mapping[str, str] | None = None,
        content_length: int = 0,
        body: str = "",
        timing_ms: int = 0,
        parameters: Mapping[str, Any] | None = None,
        provenance: Mapping[str, Any] | None = None,
    ) -> BaselineObservation:
        """Capture a baseline observation."""
        mission = self.get(mission_id)
        baseline = self.baseline.capture(
            mission_id=mission_id,
            asset_key=asset_key,
            request_fingerprint=request_fingerprint,
            status_code=status_code,
            headers=headers,
            content_length=content_length,
            body=body,
            timing_ms=timing_ms,
            parameters=parameters,
            provenance=provenance,
        )
        mission.baselines.append(baseline)
        return baseline

    def differential_test(
        self,
        mission_id: str,
        *,
        asset_key: str,
        baseline: BaselineObservation | None = None,
        test: TestResponse | None = None,
        classification_hint: str = "",
    ) -> Any:
        """Run a differential test against the matching baseline."""
        mission = self.get(mission_id)
        effective_baseline = baseline or self.baseline.match(asset_key=asset_key)
        if effective_baseline is None or test is None:
            return None
        result = self.differential.compare(
            mission_id=mission_id,
            asset_key=asset_key,
            baseline=effective_baseline,
            test=test,
            classification_hint=classification_hint,
        )
        mission.differential_results.append(result)
        return result

    # -- branches ------------------------------------------------------------

    def fork_branch(
        self,
        mission_id: str,
        *,
        hypothesis_id: str,
        rationale: str,
        parent_branch_id: str = "",
        priority: float = 0.5,
    ) -> MissionBranch:
        """Open a mission branch."""
        mission = self.get(mission_id)
        branch = self.branches.create(
            mission_id=mission_id,
            hypothesis_id=hypothesis_id,
            rationale=rationale,
            parent_branch_id=parent_branch_id,
            priority=priority,
        )
        mission.branches.append(branch)
        self._trace_mission(mission, MissionEventType.MISSION_BRANCH_CREATED, branch_id=branch.branch_id)
        return branch

    def resolve_branch(self, mission_id: str, branch_id: str, *, outcome: str) -> MissionBranch:
        """Resolve a mission branch."""
        mission = self.get(mission_id)
        for index, branch in enumerate(mission.branches):
            if branch.branch_id == branch_id:
                resolved = self.branches.resolve(branch, outcome=outcome)
                mission.branches[index] = resolved
                return resolved
        raise KeyError(branch_id)

    # -- confidence / impact / cascade ----------------------------------------

    def compute_confidence(
        self,
        mission_id: str,
        *,
        detection_evidence: float = 0.0,
        behavioral_evidence: float = 0.0,
        independent_verification: float = 0.0,
        impact_evidence: float = 0.0,
        reproducibility: float = 0.0,
        tool_reliability: float = 0.5,
        evidence_quality: float = 0.0,
        corroboration: int = 0,
        historical_target_behavior: float = 0.0,
        weights: dict[str, float] | None = None,
    ) -> ConfidenceResult:
        """Compute an evidence-driven confidence score."""
        inp = ConfidenceInput(
            detection_evidence=detection_evidence,
            behavioral_evidence=behavioral_evidence,
            independent_verification=independent_verification,
            impact_evidence=impact_evidence,
            reproducibility=reproducibility,
            tool_reliability=tool_reliability,
            evidence_quality=evidence_quality,
            corroboration=corroboration,
            historical_target_behavior=historical_target_behavior,
        )
        return self.confidence.compute(inp, weights=weights)

    def analyze_impact(self, mission_id: str, *, finding: dict[str, Any], confidence: float = 0.0, reproducible: bool = True) -> ImpactAnalysis:
        """Compute impact analysis for a validated finding."""
        mission = self.get(mission_id)
        analysis = self.impact.analyze(
            finding=finding,
            mission_id=mission_id,
            confidence=confidence,
            reproducible=reproducible,
        )
        mission.impact_analyses.append(analysis)
        return analysis

    def cascade_findings(self, mission_id: str) -> list[MissionHypothesis]:
        """Open follow-on hypotheses from validated findings (reassessment)."""
        mission = self.get(mission_id)
        follow_ons: list[MissionHypothesis] = []
        validated = [
            finding
            for finding in mission.context.findings
            if finding.get("stage") in ("verified", "proven", "report_ready")
        ]
        for finding in validated:
            trigger = CascadeTrigger(
                finding_id=str(finding.get("finding_id", "")),
                vulnerability_class=str(finding.get("vulnerability_class", "unknown_behavior")),
                asset_key=str(finding.get("asset_key") or finding.get("target") or ""),
                detail=finding,
            )
            for hypothesis in self.cascade.cascade(trigger):
                hypothesis = type(hypothesis)(
                    mission_id=mission_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    statement=hypothesis.statement,
                    category=hypothesis.category,
                    validation_strategy=hypothesis.validation_strategy,
                    priority=hypothesis.priority,
                    confidence=hypothesis.confidence,
                    provenance=hypothesis.provenance,
                )
                if not any(h.statement == hypothesis.statement for h in mission.hypotheses):
                    mission.upsert_hypothesis(hypothesis)
                    follow_ons.append(hypothesis)
        self._trace_mission(mission, MissionEventType.MISSION_REASSESSMENT_STARTED, follow_ons=len(follow_ons))
        return follow_ons

    # -- evidence / findings --------------------------------------------------

    def register_finding(
        self,
        mission_id: str,
        *,
        finding_id: str = "",
        vulnerability_class: str,
        title: str = "",
        description: str = "",
        asset_key: str = "",
        target: str = "",
        severity: str = "info",
        tool: str = "",
        stage: FindingStage | str = FindingStage.CANDIDATE,
        evidence_refs: tuple[str, ...] | list[str] = (),
        confidence: float = 0.0,
    ) -> dict[str, Any]:
        """Register (or update) a finding on the mission context.

        Registration is deduplicated: a candidate carrying the same
        vulnerability class and asset (endpoint) as an existing finding is
        merged into it — accumulating unique evidence references — instead of
        creating a duplicate. Repeated identical observations from the same
        tool, target and endpoint therefore never multiply findings, and a
        single candidate per class+endpoint is what a validated hypothesis may
        later promote.
        """
        mission = self.get(mission_id)
        stage_value = stage.value if isinstance(stage, FindingStage) else str(stage)
        finding = {
            "finding_id": finding_id or generate_id(),
            "mission_id": mission_id,
            "vulnerability_class": vulnerability_class,
            "title": title or f"{vulnerability_class} on {asset_key or target}",
            "description": description,
            "asset_key": asset_key,
            "target": target,
            "severity": severity,
            "tool": tool,
            "stage": stage_value,
            "evidence_refs": list(evidence_refs),
            "confidence": confidence,
            "updated_at": utcnow_iso(),
        }
        for index, existing in enumerate(mission.context.findings):
            if existing.get("finding_id") == finding["finding_id"]:
                merged = {**existing, **finding, "stage": _promote_stage(existing.get("stage", ""), stage_value)}
                mission.context.findings[index] = merged
                self._trace_mission(
                    mission,
                    MissionEventType.MISSION_FINDING_VALIDATED
                    if stage_value in ("verified", "proven", "report_ready")
                    else MissionEventType.MISSION_FINDING_CREATED,
                    finding_id=finding["finding_id"],
                )
                return merged
        if stage_value == FindingStage.CANDIDATE.value:
            # Deduplicate findings by class + asset (endpoint) so a repeated
            # observation never spawns a second candidate that could later be
            # promoted into a duplicate validated finding. The merge keeps the
            # existing (possibly already promoted) stage and accumulates unique
            # evidence references.
            for index, existing in enumerate(mission.context.findings):
                if (
                    existing.get("vulnerability_class") == vulnerability_class
                    and existing.get("asset_key") == asset_key
                ):
                    merged_refs = list(
                        dict.fromkeys([*(existing.get("evidence_refs") or ()), *finding["evidence_refs"]])
                    )
                    merged = {**existing, **finding, "evidence_refs": merged_refs}
                    merged["stage"] = _promote_stage(existing.get("stage", ""), stage_value)
                    mission.context.findings[index] = merged
                    self._trace_mission(
                        mission,
                        MissionEventType.MISSION_FINDING_CREATED,
                        finding_id=finding["finding_id"],
                    )
                    return merged
        # When a finding is promoted to a validated state, link its evidence
        # and record proof in the mission context for tracking.
        if stage_value in ("verified", "proven", "report_ready"):
            self._link_finding_evidence(mission, finding)
        mission.context.findings.append(finding)
        self._trace_mission(mission, MissionEventType.MISSION_FINDING_CREATED, finding_id=finding["finding_id"])
        return finding

    def _link_finding_evidence(self, mission: OrchestratedMission, finding: dict[str, Any]) -> None:
        """Link finding evidence to the mission context's evidence/proofs dicts.

        Validated findings must have their evidence and proof tracked in the
        mission context so the aggregate counts (evidence_count, proof_count)
        are accurate and internally consistent.
        """
        finding_id = finding.get("finding_id")
        evidence_refs = finding.get("evidence_refs", [])
        vulnerability_class = finding.get("vulnerability_class", "unknown")
        asset_key = finding.get("asset_key", "")
        stage = finding.get("stage", "")

        # Link each evidence reference (observation ID) to the finding in evidence dict
        for obs_id in evidence_refs:
            obs = mission.observation(obs_id)
            if obs is None:
                continue
            key = f"finding:{finding_id}:{obs_id}"
            mission.context.evidence[key] = {
                "finding_id": finding_id,
                "observation_id": obs_id,
                "vulnerability_class": vulnerability_class,
                "asset_key": asset_key,
                "stage": stage,
                "observation_type": obs.observation_type,
                "confidence": obs.confidence,
                "recorded_at": utcnow_iso(),
            }

        # Record proof entry for the finding
        proof_key = f"proof:{finding_id}"
        if proof_key not in mission.context.proofs:
            mission.context.proofs[proof_key] = {
                "finding_id": finding_id,
                "vulnerability_class": vulnerability_class,
                "asset_key": asset_key,
                "stage": stage,
                "evidence_refs": list(evidence_refs),
                "proof_depth": finding.get("proof_depth", "minimal"),
                "created_at": utcnow_iso(),
            }

    # -- checkpoints ----------------------------------------------------------

    def checkpoint(self, mission_id: str, *, label: str = "") -> dict[str, Any]:
        """Snapshot the full resumable mission state."""
        mission = self.get(mission_id)
        snapshot = {
            "checkpoint_id": generate_id(),
            "mission_id": mission_id,
            "label": label or "phase-completion",
            "planning": (
                getattr(self.planning, "to_dict", lambda: None)() if self.planning is not None else None
            ),
            "mission": mission.to_dict(),
            "observations": [observation.to_dict() for observation in mission.observations],
            "hypotheses": [hypothesis.to_dict() for hypothesis in mission.hypotheses],
            "decisions": [decision.to_dict() for decision in mission.decisions],
            "branches": [branch.to_dict() for branch in mission.branches],
            "negative_evidence": [record.to_dict() for record in mission.negative_evidence],
            "baselines": [baseline.to_dict() for baseline in mission.baselines],
            "trace": [entry.to_dict() for entry in mission.trace],
            "coverage": mission.coverage_dict(),
            "context": mission.context.to_dict(),
            "created_at": utcnow_iso(),
        }
        mission.checkpoints.append(snapshot)
        self._trace_mission(mission, MissionEventType.MISSION_CHECKPOINT_CREATED, checkpoint_id=snapshot["checkpoint_id"])
        return snapshot

    def resume_from_checkpoint(self, mission_id: str, checkpoint: dict[str, Any]) -> OrchestratedMission:
        """Restore a mission from a persisted checkpoint snapshot."""
        mission = self.get(mission_id)
        if "negative_evidence" in checkpoint:
            self.negative.extend(
                NegativeEvidenceRecord(**record) for record in checkpoint["negative_evidence"]
            )
        if "trace" in checkpoint:
            from hunterx.domain.mission_orchestration.models import ReasoningTraceEntry

            entries = [ReasoningTraceEntry(**entry) for entry in checkpoint["trace"]]
            self.trace.extend(entries)
            mission.trace.extend(entries)
        if "baselines" in checkpoint:
            from hunterx.domain.mission_orchestration.models import BaselineObservation

            for record in checkpoint["baselines"]:
                mission.baselines.append(BaselineObservation(**record))
        mission.runs.append(
            MissionRun(
                run_id=generate_id(),
                mission_id=mission_id,
                status=MissionRunStatus.RESUMED,
                resumed_from_run_id=mission.runs[-1].run_id if mission.runs else "",
                checkpoint_id=str(checkpoint.get("checkpoint_id", "")),
            )
        )
        return mission

    def explain_decision(self, mission_id: str, decision_id: str = "") -> dict[str, Any] | None:
        """Return the explainable decision record (or the latest)."""
        mission = self.get(mission_id)
        if decision_id:
            decision = mission.decision(decision_id)
        else:
            decision = mission.decisions[-1] if mission.decisions else None
        return decision.to_dict() if decision else None

    def explain_next(self, mission_id: str) -> dict[str, Any]:
        """Explain why the highest-ranked candidate action is next."""
        decision = self.decide_next(mission_id)
        if decision is None:
            return {"explanation": "no actionable candidates", "decision": None}
        mission = self.get(mission_id)
        return {
            "next_action": decision.next_action,
            "capability": decision.capability,
            "tool": decision.tool_id,
            "reason": decision.reason,
            "expected_result": decision.expected_result,
            "priority": decision.priority,
            "dependencies": list(decision.dependencies),
            "alternatives": [list(pair) for pair in decision.alternatives],
            "information_gain": decision.information_gain,
            "factors": decision.factors,
            "phase": mission.current_phase.value,
        }

    # -- helpers ---------------------------------------------------------------

    def _hypothesize_from_observation(self, mission: OrchestratedMission, observation: MissionObservation) -> None:
        """Create a hypothesis from a meaningful observation (evidence-grounded).

        Hypotheses are conjectures that probing can validate — they are only
        created when the observation actually carries data supporting them, and
        never merely because a tool ran. Creation is idempotent by statement.
        """
        content = observation.content
        if not has_meaningful_content(content):
            return
        asset_key = observation.asset_key or mission.context.target_id or "target"
        proposed: list[tuple[str, HypothesisType, dict[str, Any]]] = []
        if observation.observation_type == "vulnerability":
            # Every candidate produces its own class-specific hypothesis so
            # multiple classes in one observation chain into separate probes.
            # Informational results (WAF/DNS/tech detection, fingerprinting,
            # robots.txt, WHOIS/RDAP) are intelligence, never hypotheses.
            for candidate in _vulnerability_candidates(content):
                if not isinstance(candidate, dict) or not candidate:
                    continue
                if not _is_vulnerability_signal(candidate):
                    # Explicit classification (Phase 4): an informational
                    # candidate is never silently dropped. A security-relevant
                    # config signal (e.g. nuclei ``deprecated-tls`` →
                    # ``security-misconfiguration``) becomes a low-priority
                    # MISCONFIGURATION hypothesis; everything else is recorded
                    # as informational evidence on the context.
                    canonical = _vulnerability_class_of(candidate)
                    from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

                    if canonical and is_vulnerability_class(canonical):
                        endpoint = _candidate_field(candidate, "endpoint")
                        statement = (
                            f"{endpoint or asset_key} exposes a security misconfiguration "
                            f"(informational: {_template_of(candidate) or canonical})"
                        )
                        proposed.append(
                            (
                                statement,
                                HypothesisType.MISCONFIGURATION,
                                {
                                    "vulnerability_class": canonical,
                                    "endpoint": endpoint or "",
                                    "informational": True,
                                },
                                0.45,
                            )
                        )
                    else:
                        mission.context.evidence[f"info:{observation.observation_id}:{canonical or 'unknown'}"] = {
                            "kind": "informational",
                            "observation_id": observation.observation_id,
                            "tool_id": observation.tool_id or "",
                            "asset_key": asset_key,
                            "class": canonical,
                            "content": _candidate_summary(candidate),
                            "classified": "non_actionable",
                            "recorded_at": utcnow_iso(),
                        }
                    continue
                class_id = _vulnerability_class_of(candidate)
                endpoint = _candidate_field(candidate, "endpoint")
                parameter = _candidate_field(candidate, "parameter")
                statement = f"{endpoint or asset_key} may be affected by {class_id}"
                category = _category_for_template(class_id)
                extra: dict[str, Any] = {}
                if class_id != "unknown":
                    extra = {
                        "vulnerability_class": class_id,
                        "endpoint": endpoint or "",
                        "parameter": parameter or "",
                    }
                if statement:
                    proposed.append((statement, category, extra, 0.0))
        elif observation.observation_type in ("technology", "tech"):
            name = str(content.get("name") or "").strip()
            if name:
                proposed.append((f"{asset_key} runs technology {name}", HypothesisType.UNKNOWN_BEHAVIOR, {}, 0.0))
        elif observation.observation_type in ("service", "port"):
            service = str(content.get("service") or content.get("name") or "").strip()
            if service:
                proposed.append((f"{asset_key} exposes service {service}", HypothesisType.UNKNOWN_BEHAVIOR, {}, 0.0))
        elif observation.observation_type in ("endpoint", "url", "api", "graphql", "javascript", "route"):
            for endpoint in _endpoint_urls(content):
                # JS analysis surfaces relative paths (``/rest/...``) that must
                # resolve against the mission target so downstream probes stay
                # absolute and loopback-checkable; third-party references are
                # not the target's attack surface and are skipped.
                if observation.observation_type == "javascript":
                    endpoint = _resolve_endpoint(str(endpoint), asset_key)
                    if not endpoint or not _same_origin(endpoint, asset_key):
                        continue
                proposed.append((f"{endpoint} is a reachable endpoint of the target", HypothesisType.UNKNOWN_BEHAVIOR, {"endpoint": endpoint}, 0.0))
                # Query parameters on the discovered surface drive targeted
                # hypotheses (e.g. ``/redirect?to=`` → open redirect).
                for parameter in _url_query_parameters(endpoint):
                    for class_id, class_priority in _classes_for_surface(parameter):
                        proposed.append(
                            (
                                f"The '{parameter}' parameter on {endpoint} may be susceptible to {class_id}",
                                _category_for_template(class_id),
                                {"vulnerability_class": class_id, "endpoint": endpoint, "parameter": parameter},
                                class_priority,
                            )
                        )
        elif observation.observation_type in ("asset", "subdomain", "host", "hostname", "domain") and asset_key and asset_key != "target":
            proposed.append((f"{asset_key} is part of the target's attack surface", HypothesisType.UNKNOWN_BEHAVIOR, {}, 0.0))
        elif observation.observation_type == "parameter":
            parameters: list[str] = []
            methods: dict[str, str] = {}
            raw = content.get("parameters") if isinstance(content, dict) else None
            if raw is None:
                raw = content.get("parameter") if isinstance(content, dict) else None
            for parameter in _as_list(raw):
                if isinstance(parameter, dict):
                    name = str(parameter.get("name") or parameter.get("parameter") or "").strip()
                    if name:
                        parameters.append(name)
                        method = str(parameter.get("method") or "").strip().upper()
                        if method in ("POST", "PUT"):
                            methods[name] = method
                elif parameter is not None:
                    name = str(parameter).strip()
                    if name:
                        parameters.append(name)
            for parameter in parameters:
                for class_id, class_priority in _classes_for_surface(parameter):
                    provenance_extra: dict[str, Any] = {
                        "vulnerability_class": class_id,
                        "endpoint": asset_key,
                        "parameter": str(parameter),
                    }
                    method = methods.get(parameter)
                    if method:
                        provenance_extra["method"] = method
                    proposed.append(
                        (
                            f"The '{parameter}' parameter on {asset_key} may be susceptible to {class_id}",
                            _category_for_template(class_id),
                            provenance_extra,
                            class_priority,
                        )
                    )
        if not proposed:
            return
        for statement, category, provenance_extra, explicit_priority in proposed:
            behavior_class = (
                BehaviorClass.KNOWN
                if category is not HypothesisType.UNKNOWN_BEHAVIOR
                else BehaviorClass.NOVEL_CANDIDATE
            )
            try:
                self.add_hypothesis(
                    mission.mission_id,
                    statement=statement,
                    category=category,
                    supporting=(observation.observation_id,),
                    confidence=max(0.2, min(1.0, observation.confidence or 0.4)),
                    priority=(
                        explicit_priority
                        if explicit_priority > 0
                        else _priority_for_hypothesis(category, observation.observation_type)
                    ),
                    proposed_by=f"observation:{observation.tool_id or 'tool'}",
                    behavior_class=behavior_class,
                    provenance_hint={
                        "observation_id": observation.observation_id,
                        "observation_type": observation.observation_type,
                        "asset_key": asset_key,
                        **provenance_extra,
                    },
                )
            except Exception:  # noqa: BLE001 - hypothesis creation is best-effort
                continue

    def _hypothesize_from_context(self, mission: OrchestratedMission) -> None:
        """Derive security hypotheses from the canonical attack-surface model.

        Endpoints and parameters recorded in the mission context are actionable
        surface: a discovered parameter with a class hint (``q`` → SQL
        injection, ``id`` → IDOR, ``url`` → SSRF, ``to`` → open redirect, ...)
        produces a targeted vulnerability hypothesis even when the producing
        scanner payload had a different shape (e.g. httpx technologies with an
        ``asset`` URL). Idempotent by statement.
        """
        proposed: list[tuple[str, HypothesisType, dict[str, Any], float]] = []
        for param_entry in mission.context.parameters.values():
            if not isinstance(param_entry, dict):
                continue
            endpoint = str(param_entry.get("key") or "")
            parameter = str(param_entry.get("parameter") or "")
            if not endpoint or not parameter:
                continue
            method = str(param_entry.get("method") or "").strip().upper()
            for class_id, class_priority in _classes_for_surface(parameter):
                provenance_extra: dict[str, Any] = {
                    "vulnerability_class": class_id,
                    "endpoint": endpoint,
                    "parameter": parameter,
                }
                if method in ("POST", "PUT"):
                    provenance_extra["method"] = method
                statement = f"The '{parameter}' parameter on {endpoint} may be susceptible to {class_id}"
                proposed.append(
                    (
                        statement,
                        _category_for_template(class_id),
                        provenance_extra,
                        class_priority,
                    )
                )
        # Restricted/error HTTP statuses on discovered endpoints are candidate
        # access-control / routing / proxy discrepancies: a 401/402/403/404/
        # 405/502 response marks a resource that may be reachable through an
        # alternate representation. The hypothesis describes the potential
        # discrepancy (never "got a status code"), and the capability probe
        # independently confirms meaningful access or honestly refutes it.
        for endpoint_entry in mission.context.endpoints.values():
            if not isinstance(endpoint_entry, dict):
                continue
            endpoint = str(endpoint_entry.get("key") or "")
            status = endpoint_entry.get("status")
            if not endpoint or status not in (401, 402, 403, 404, 405, 502):
                continue
            statement = (
                f"The resource on {endpoint} returned {status} and may be reachable "
                f"through an alternate representation (access-control/routing/proxy discrepancy)"
            )
            extra: dict[str, Any] = {
                "vulnerability_class": "http-access-differential",
                "endpoint": endpoint,
                "observed_status": int(status),
            }
            if endpoint_entry.get("proof_marker"):
                extra["proof_marker"] = str(endpoint_entry["proof_marker"])
            proposed.append(
                (statement, HypothesisType.AUTHORIZATION_ISSUE, extra, 0.7)
            )
        for statement, category, provenance_extra, explicit_priority in proposed:
            if self._has_open_hypothesis(
                mission,
                str(provenance_extra.get("vulnerability_class") or ""),
                str(provenance_extra.get("endpoint") or ""),
            ):
                continue
            behavior_class = (
                BehaviorClass.KNOWN
                if category is not HypothesisType.UNKNOWN_BEHAVIOR
                else BehaviorClass.NOVEL_CANDIDATE
            )
            try:
                self.add_hypothesis(
                    mission.mission_id,
                    statement=statement,
                    category=category,
                    supporting=(),
                    confidence=0.6,
                    priority=(explicit_priority if explicit_priority > 0 else 0.6),
                    proposed_by="attack-surface-model",
                    behavior_class=behavior_class,
                    provenance_hint=dict(provenance_extra),
                )
            except Exception:  # noqa: BLE001 - hypothesis creation is best-effort
                continue

    @staticmethod
    def _has_open_hypothesis(mission: OrchestratedMission, class_id: str, endpoint: str) -> bool:
        """Return ``True`` when a hypothesis already covers class+endpoint.

        Guards the attack-surface-model against duplicating a vulnerability
        hypothesis that a scanner observation (or an earlier derivation)
        already produced for the same class and endpoint — settled or not
        (statements differ, so idempotency-by-statement alone cannot merge
        them; re-deriving a validated or refuted surface would duplicate
        probes).
        """
        if not class_id:
            return False
        for hypothesis in mission.hypotheses:
            provenance = hypothesis.provenance or {}
            if (
                str(provenance.get("vulnerability_class") or "") == class_id
                and (str(provenance.get("endpoint") or "") == endpoint or not endpoint)
            ):
                return True
        return False

    def _populate_context(self, mission: OrchestratedMission, observation: MissionObservation) -> None:
        """Update the target-centric context from a normalized observation.

        The observation content is treated as data, never as instructions. The
        context maps are keyed by (type:key) so the same target keeps a single
        authoritative record per discovered item.

        An observation only creates context entities when it carries meaningful
        evidence: an empty-but-successful result (or junk with no usable
        values) must never fabricate phantom assets, services, technologies or
        endpoints in the target model.
        """
        content = observation.content
        if not has_meaningful_content(content):
            return
        self._seed_root_asset(mission)
        asset_key = observation.asset_key or str(content.get("key", ""))
        observation_type = observation.observation_type

        if observation_type in ("asset", "subdomain", "host", "hostname", "domain"):
            for discovered in _discovered_assets(content, asset_key):
                mission.context.assets[f"asset:{discovered}"] = {"key": discovered, "content": content}
        elif observation_type in ("technology", "tech"):
            names = _technology_names(content)
            for name in names:
                if not name or not asset_key:
                    continue
                mission.context.technologies[f"tech:{asset_key}:{name}"] = {
                    "key": asset_key,
                    "content": content,
                }
        elif observation_type in ("service", "port"):
            if not asset_key:
                return
            for key, identity in _service_entries(content, asset_key):
                mission.context.services[key] = {"key": asset_key, "content": content, "identity": identity}
        elif observation_type in ("endpoint", "url", "api", "graphql", "javascript", "route"):
            endpoints = _endpoint_urls(content)
            records = [
                entry
                for entry in _endpoint_records(content)
                if isinstance(entry, dict) and (entry.get("parameters") or entry.get("method"))
            ]
            for entry in _as_list(content.get("technologies")):
                if not isinstance(entry, dict):
                    continue
                url = str(entry.get("asset") or entry.get("url") or "").strip()
                if url:
                    endpoints.append(url)
            status = content.get("status_code") if isinstance(content, dict) else None
            proof_marker = content.get("proof_marker") if isinstance(content, dict) else None
            for endpoint in endpoints:
                if not str(endpoint).strip():
                    continue
                # JS analysis surfaces relative paths (``/rest/...``) that must
                # resolve against the mission target so downstream probes stay
                # absolute and loopback-checkable. Third-party references a JS
                # bundle embeds (SoundCloud embeds, public RPC endpoints, SVG
                # namespaces, ...) are NOT the target's attack surface and are
                # skipped.
                if observation.observation_type == "javascript":
                    endpoint = _resolve_endpoint(str(endpoint), mission.context.target_id)
                    if not endpoint or not _same_origin(endpoint, mission.context.target_id):
                        continue
                entry: dict[str, Any] = {"key": str(endpoint), "content": content}
                if status is not None:
                    entry["status"] = int(status)
                if proof_marker:
                    entry["proof_marker"] = str(proof_marker)
                mission.context.endpoints[f"endpoint:{endpoint}"] = entry
                # Query parameters on the discovered URL become parameter
                # context so downstream capabilities can target them.
                for parameter in _url_query_parameters(str(endpoint)):
                    mission.context.parameters[f"param:{endpoint}:{parameter}"] = {
                        "key": str(endpoint),
                        "parameter": parameter,
                    }
                # Structured records (crawler API endpoints / form actions)
                # carry ``parameters`` and an explicit HTTP ``method``; a
                # POST/PUT form field must be probed through a request body,
                # which the downstream probes honor via the recorded method.
                for record in records:
                    record_url = str(
                        record.get("url") or record.get("endpoint") or record.get("path") or ""
                    ).strip()
                    if record_url != str(endpoint):
                        continue
                    method = str(record.get("method") or "").strip().upper()
                    for param in _as_list(record.get("parameters")):
                        if not isinstance(param, dict):
                            continue
                        name = str(param.get("name") or "").strip()
                        if not name:
                            continue
                        param_entry: dict[str, Any] = {
                            "key": str(endpoint),
                            "parameter": name,
                        }
                        if method in ("POST", "PUT"):
                            param_entry["method"] = method
                        mission.context.parameters[f"param:{endpoint}:{name}"] = param_entry
        elif observation_type == "parameter":
            raw = content.get("parameters")
            if raw is None:
                raw = content.get("parameter")
            # Arjun's payload nests its findings: ``{"parameters": {"findings":
            # [{"name", "endpoint", "method"}, ...]}}``.
            if isinstance(raw, dict):
                raw = raw.get("findings") or raw.get("parameters") or []
            parameter_records: list[dict[str, str]] = []
            for item in _as_list(raw):
                if isinstance(item, dict):
                    name = str(item.get("name") or item.get("parameter") or "").strip()
                    endpoint = str(item.get("endpoint") or asset_key or "").strip()
                    method = str(item.get("method") or "").strip().upper()
                    if name:
                        parameter_records.append(
                            {"name": name, "endpoint": endpoint, "method": method}
                        )
                elif item is not None and str(item).strip():
                    parameter_records.append(
                        {"name": str(item).strip(), "endpoint": asset_key, "method": ""}
                    )
            for record in parameter_records:
                entry: dict[str, Any] = {
                    "key": record["endpoint"],
                    "parameter": record["name"],
                }
                if record["method"] in ("POST", "PUT"):
                    entry["method"] = record["method"]
                mission.context.parameters[f"param:{record['endpoint']}:{record['name']}"] = entry
        elif observation_type == "vulnerability":
            for finding in _vulnerability_candidates(content):
                if not isinstance(finding, dict) or not finding:
                    continue
                if not _is_vulnerability_signal(finding):
                    # Informational scanner results (WAF detection, tech / DNS /
                    # SPF / MX fingerprinting, robots.txt, WHOIS / RDAP, ...)
                    # stay observations/intelligence: they never enter the
                    # candidate-finding pipeline.
                    continue
                class_id = _vulnerability_class_of(finding)
                endpoint = _candidate_field(finding, "endpoint")
                parameter = _candidate_field(finding, "parameter")
                self.register_finding(
                    mission.mission_id,
                    vulnerability_class=class_id,
                    asset_key=endpoint or asset_key or mission.context.target_id or "target",
                    target=mission.context.target_id or "",
                    severity=str(finding.get("severity") or "info"),
                    tool=observation.tool_id or "",
                    stage=FindingStage.CANDIDATE,
                    evidence_refs=(observation.evidence_ref or observation.observation_id,),
                    description=f"candidate from {observation.tool_id or 'tool'} observation {observation.observation_id}",
                )
                if parameter:
                    mission.context.parameters[f"param:{endpoint or asset_key}:{parameter}"] = {
                        "key": endpoint or asset_key,
                        "parameter": parameter,
                    }

    def _objectives_satisfied(self, mission: OrchestratedMission) -> bool:
        """Return ``True`` when the mission has genuinely satisfied its objectives.

        The completion gate (Phase 12): a full security assessment is complete
        only when its objective completion contract is satisfied — meaningful
        work happened, no pending plan work remains, no actionable hypothesis is
        silently left open, and every mandatory dimension (active testing,
        browser, attack paths, validation) was assessed or explicitly
        classified. Reconnaissance completion alone never satisfies the
        objectives, and a mission that never ran any work is never reported as
        complete.
        """
        has_work = bool(mission.observations) or bool(mission.hypotheses) or mission.budget.executions_used > 0
        if not has_work:
            return False
        satisfied, _unmet = self._completion_contract_gate(mission)
        return bool(satisfied)

    @staticmethod
    def _has_open_high_value_work(mission: OrchestratedMission) -> bool:
        """Return ``True`` when a high-value hypothesis is still unresolved."""
        return any(
            MissionPolicyEngine._is_high_value(hypothesis)
            and hypothesis.state.value in _OPEN_HYPOTHESIS_STATES
            for hypothesis in mission.hypotheses
        )

    @staticmethod
    def _has_pending_plan_work(mission: OrchestratedMission) -> bool:
        """Return ``True`` when the planning graph still carries non-terminal work."""
        return any(
            not action.status.is_terminal
            for action in mission.mission.graph.actions.values()
        )

    @staticmethod
    def _blocked_unresolved(mission: OrchestratedMission) -> bool:
        """Return ``True`` when open work remains but cannot be discharged.

        A mission is *blocked* (honest incomplete terminal) when high-value
        hypotheses remain open with no bound, non-terminal probe action — the
        probe capabilities are unavailable or the target is not probeable. This
        is never reported as success and never as a budget exhaustion.
        """
        open_states = _OPEN_HYPOTHESIS_STATES
        for hypothesis in mission.hypotheses:
            if hypothesis.state.value not in open_states:
                continue
            provenance = hypothesis.provenance or {}
            if not str(provenance.get("vulnerability_class") or "").strip():
                continue
            return True
        return False

    def _advance_to_completed(self, mission_id: str) -> None:
        """Walk the planning state machine to COMPLETED through legal hops.

        The Sprint 027 state machine only permits REASSESSMENT → REPORTING →
        COMPLETED at the tail, so the orchestrator advances the mission along
        allowed transitions instead of forcing a forbidden jump.
        """
        if self.planning is None:
            return
        from hunterx.domain.adaptive_mission_planning.enums import MissionState

        current = self.planning.get_mission(mission_id).state
        if current is MissionState.COMPLETED:
            return
        if current is MissionState.CANCELLED or current is MissionState.FAILED:
            return
        if current is MissionState.CREATED:
            self.planning.transition(mission_id, MissionState.SCOPING)
        if current is MissionState.REPORTING:
            self.planning.complete(mission_id)
            return
        if current is MissionState.REASSESSMENT:
            self.planning.transition(mission_id, MissionState.REPORTING)
            self.planning.complete(mission_id)
            return
        # walk forward: any active state → REASSESSMENT → REPORTING → COMPLETED
        self.planning.transition(mission_id, MissionState.REASSESSMENT)
        self.planning.transition(mission_id, MissionState.REPORTING)
        self.planning.complete(mission_id)

    def _trace_mission(self, mission: OrchestratedMission, event: MissionEventType, **payload: Any) -> None:
        """Append a mission event to the context history."""
        mission.context.history.append(
            {"event": event.value, **{key: value for key, value in payload.items()}}
        )

    def _record_trace(
        self,
        mission: OrchestratedMission,
        *,
        kind: ReasoningTraceKind | str,
        node_id: str,
        content: dict[str, Any],
        parent_entry_id: str = "",
    ) -> None:
        """Record a trace entry in the engine and mirror it on the mission."""
        entry = self.trace.record(
            mission_id=mission.mission_id,
            kind=kind,
            node_id=node_id,
            content=content,
            parent_entry_id=parent_entry_id,
        )
        mission.trace.append(entry)

    def record_ai_trace(self, mission_id: str, *, decision_id: str = "", **trace: Any) -> None:
        """Record an AI-invocation provenance trace entry (best-effort).

        Observability only: captures whether the AI was invoked, the suggestion
        latency, the proposed action, the acceptance state and the final
        ``ai_assisted`` value. Never affects the decision or mission state.
        """
        try:
            mission = self.get(mission_id)
        except Exception:  # noqa: BLE001 - provenance recording is best-effort
            return
        self._record_trace(
            mission,
            kind=ReasoningTraceKind.DECISION,
            node_id=decision_id or mission_id,
            content=dict(trace),
        )

    def _last_entry_id(self, mission: OrchestratedMission) -> str:
        """Return the last trace entry id for parent chaining."""
        return mission.trace[-1].entry_id if mission.trace else ""


def _objectives_for(objective: MissionObjective) -> list[str]:
    """Return the canonical objectives for an orchestration objective."""
    objectives = [
        "understand_target",
        "build_target_model",
        "discover_attack_surface",
        "classify_assets",
        "generate_hypotheses",
        "select_tools",
        "execute_actions",
        "interpret_results",
        "update_target_memory",
        "correlate_evidence",
        "generate_new_hypotheses",
        "validate_findings",
        "prove_impact",
        "generate_validate_poc",
        "reassess_target",
        "discover_new_attack_paths",
        "finalize_mission",
    ]
    return objectives


def _normalize_content(raw: Any) -> dict[str, Any]:
    """Normalize a raw tool content payload into a JSON-safe mapping."""
    if isinstance(raw, dict):
        return raw
    return {"value": raw}


def _as_list(value: Any) -> list[Any]:
    """Return a value as a list (``None`` → empty)."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _template_of(finding: Any) -> str:
    """Extract the vulnerability template/class identifier from a candidate.

    Accepts the canonical keys used by adapters (``template_id`` /
    ``template_name`` from nuclei) and the generic ``template``/``class``
    keys used elsewhere.
    """
    if not isinstance(finding, dict):
        return ""
    for key in ("template_id", "template_name", "template", "class"):
        value = finding.get(key)
        if value is not None:
            return str(value).strip()
    return ""


def _vulnerability_candidates(content: Any) -> list[Any]:
    """Flatten a scanner observation payload into candidate records.

    Scanner adapters emit ``{"candidates": [...], "count": N}``; nuclei emits
    ``{"findings": [...]}``; some paths use ``content["content"]``. All of
    these are flattened into one candidate list so every candidate reaches the
    hypothesis/finding pipeline with its real class.
    """
    if isinstance(content, list):
        return content
    if not isinstance(content, dict):
        return []
    for key in ("candidates", "findings", "vulnerabilities", "content"):
        value = content.get(key)
        if isinstance(value, list):
            return value
    return [content]


def _vulnerability_class_of(candidate: Any) -> str:
    """Return the canonical vulnerability class of a candidate record.

    Real scanner templates are canonicalized to a probeable capability class
    (e.g. nuclei ``swagger-api`` -> ``api-security``) so the engine can select a
    targeted differential probe for the observed surface.
    """
    raw = ""
    if isinstance(candidate, dict):
        value = candidate.get("vulnerability_class")
        raw = str(value).strip() if value else _template_of(candidate)
    raw = raw or "unknown"
    from hunterx.domain.vulnerability_capability.registry import canonical_class

    return canonical_class(raw)


def _is_vulnerability_signal(candidate: Any) -> bool:
    """Return ``True`` when a scanner candidate is a real vulnerability signal.

    Semantic boundary: informational scanner results (WAF detection, technology
    / DNS / SPF / MX fingerprinting, robots.txt, WHOIS / RDAP lookups, ...) are
    observations/intelligence — they never become candidate findings or
    vulnerability hypotheses. Only a class the engine recognizes as a real
    vulnerability may enter the candidate pipeline. Candidates explicitly
    rated informational (``severity: info``) are also intelligence even when
    their template happens to canonicalize to a real class (e.g. nuclei
    ``http-missing-security-headers``): a generic per-page detection must
    never become a validated, report-ready finding by itself.
    """
    if not isinstance(candidate, dict) or not candidate:
        return False
    if str(candidate.get("severity") or "").strip().lower() in ("info", "informational", "none"):
        return False
    raw = candidate.get("vulnerability_class") or _template_of(candidate)
    raw = str(raw).strip() or "unknown"
    from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

    return is_vulnerability_class(raw)


def _candidate_field(candidate: Any, name: str) -> str:
    """Return a candidate field (endpoint/parameter/...) as a string.

    Scanner records use different keys (``endpoint``, ``matched_at`` for nuclei,
    ``url``, ``target``); the endpoint is resolved with these fallbacks so a
    targeted probe hits the actual matched surface, never the bare target.
    """
    if not isinstance(candidate, dict):
        return ""
    if name == "endpoint":
        for key in ("endpoint", "endpoint_id", "matched_at", "url", "target"):
            value = candidate.get(key)
            if value:
                return str(value).strip()
        return ""
    value = candidate.get(name) or candidate.get(f"{name}_id")
    return str(value).strip()


def _candidate_summary(candidate: Any) -> str:
    """Return a short JSON-safe summary of an informational scanner candidate.

    Used to record informational evidence without persisting raw secret-bearing
    payloads. Bounded to a few safe fields.
    """
    if not isinstance(candidate, dict):
        return str(candidate)[:200]
    safe: dict[str, Any] = {}
    for key in (
        "template",
        "template_id",
        "template_name",
        "info",
        "name",
        "severity",
        "type",
        "matched_at",
        "url",
        "description",
    ):
        value = candidate.get(key)
        if value not in (None, ""):
            safe[key] = value
    return json.dumps(safe, ensure_ascii=True, default=str)[:400]


#: Parameter name hints → (canonical vulnerability class, priority). Targeted
#: reasoning: a discovered parameter maps to the class its semantics imply (an
#: object-lookup ``id`` → IDOR/BOLA, a server-side ``url`` → SSRF, a redirect
#: ``to`` → open redirect, a search ``q`` → SQL injection, a ``file`` → LFI, a
#: ``cmd`` → command injection, ``password``/``username`` → authentication).
#: The engine never runs every class against an endpoint. A hint may list
#: several candidate classes; the engine derives one hypothesis per candidate
#: so a semantically ambiguous input (``id`` → IDOR *and* SQL injection) is
#: assessed by every capability its name implies — each candidate is then
#: honestly refuted or validated by differential probing.
_PARAMETER_CLASS_HINTS: dict[str, tuple[tuple[str, float], ...]] = {
    "id": (("idor", 0.8), ("sql-injection", 0.6)),
    "userid": ("idor", 0.7),
    "uid": ("idor", 0.8),
    "user_id": ("idor", 0.8),
    "resource": ("idor", 0.7),
    "item": ("idor", 0.7),
    "account": ("idor", 0.7),
    "url": ("ssrf", 0.8),
    "fetch": ("ssrf", 0.8),
    "uri": ("ssrf", 0.7),
    "redirect": ("open-redirect", 0.7),
    "next": ("open-redirect", 0.7),
    "return": ("open-redirect", 0.7),
    "to": ("open-redirect", 0.7),
    "callback": ("open-redirect", 0.7),
    "destination": ("open-redirect", 0.7),
    "q": ("sql-injection", 0.75),
    "search": ("sql-injection", 0.75),
    "query": ("sql-injection", 0.75),
    "term": ("sql-injection", 0.7),
    "keyword": ("sql-injection", 0.7),
    "file": ("lfi", 0.75),
    "path": ("lfi", 0.7),
    "dir": ("lfi", 0.7),
    "filename": ("lfi", 0.7),
    "document": ("lfi", 0.7),
    "page": ("lfi", 0.65),
    "cmd": ("command-injection", 0.8),
    "command": ("command-injection", 0.8),
    "exec": ("command-injection", 0.8),
    "run": ("command-injection", 0.7),
    "ip": ("command-injection", 0.8),
    "host": ("command-injection", 0.7),
    "hostname": ("command-injection", 0.7),
    "username": ("authentication", 0.7),
    "password": ("authentication", 0.7),
    "login": ("authentication", 0.7),
    "email": ("authentication", 0.6),
    "name": ("ssti", 0.6),
    "template": ("ssti", 0.7),
}


def _hint_matches(hint: str, name: str) -> bool:
    """Return ``True`` when ``hint`` denotes the parameter ``name``.

    Matching is token-based: ``hint`` must equal the whole name or one of its
    ``_``/``-``/``/``-separated tokens (``user_id`` → ``id``, ``callback-url``
    → ``callback``). Substring matching would misclassify short hints (``ip``
    would hit ``api``/``skip``, ``id`` would hit ``ids``) and fabricate
    attacker-injected hypotheses on unrelated parameters.
    """
    import re

    normalized = (name or "").lower()
    if hint == normalized:
        return True
    return any(hint == token for token in re.split(r"[^a-z0-9]+", normalized))


def _classes_for_surface(name: str) -> list[tuple[str, float]]:
    """Return every candidate ``(canonical_class, priority)`` for ``name``.

    A named parameter maps to the semantic classes its name implies; a hint
    with several candidates yields one class per entry (``id`` → IDOR, then
    SQL injection). An unclassified discovered input is a candidate
    *reflection* surface and therefore derives a cross-site scripting
    hypothesis: the XSS capability independently probes for unescaped
    reflection, so a non-reflecting input is honestly contradicted rather than
    ever flagged. This is the attack-surface → XSS derivation — it is driven by
    actual discovered parameters, never by a hardcoded endpoint.
    """
    for hint, candidates in _PARAMETER_CLASS_HINTS.items():
        if _hint_matches(hint, name):
            if candidates and isinstance(candidates[0], tuple):
                return list(candidates)
            return [tuple(candidates)]
    return [("xss", 0.6)]


def _class_for_parameter(name: str) -> tuple[str, float]:
    """Return ``(primary_canonical_class, priority)`` implied by a parameter name."""
    for hint, candidates in _PARAMETER_CLASS_HINTS.items():
        if _hint_matches(hint, name):
            if candidates and isinstance(candidates[0], tuple):
                return candidates[0]
            return tuple(candidates)
    return "", 0.0


def _class_for_surface(name: str) -> tuple[str, float]:
    """Return the primary class a discovered input should be probed for."""
    return _classes_for_surface(name)[0]


def _is_ipv4(value: str) -> bool:
    """Return ``True`` when ``value`` is an IPv4 literal."""
    import ipaddress

    try:
        ipaddress.IPv4Address(value)
        return True
    except (ValueError, TypeError):
        return False


def _resolve_endpoint(url: str, target: str) -> str:
    """Resolve a relative endpoint against the mission target origin.

    In-process javascript analysis yields relative paths (``/rest/...``) that
    must become absolute loopback URLs before they are probed. Already-absolute
    URLs (other origins, absolute links) pass through untouched.
    """
    from urllib.parse import urljoin, urlsplit

    if not url or not target:
        return ""
    try:
        if urlsplit(url).scheme:
            return url
        return urljoin(target, url)
    except (ValueError, TypeError):
        return ""


def _same_origin(url: str, target: str) -> bool:
    """Return ``True`` when ``url`` shares the scheme+netloc of ``target``."""
    from urllib.parse import urlsplit

    try:
        return urlsplit(url)[:2] == urlsplit(target)[:2]
    except (ValueError, TypeError):
        return False


def _url_query_parameters(url: str) -> list[str]:
    """Return the query parameter names of a discovered URL.

    A crawler URL such as ``/redirect?to=https`` exposes a ``to`` parameter
    even before a dedicated parameter tool runs; recording it lets the engine
    derive targeted hypotheses (``to`` → open redirect, ``id`` → IDOR, ...)
    directly from the discovered surface.
    """
    from urllib.parse import parse_qsl, urlsplit

    try:
        query = urlsplit(url).query
    except (ValueError, TypeError):
        return []
    # ``keep_blank_values`` keeps parameters whose value is empty (e.g. a JS
    # template ``?q=${expr}`` records ``q`` with an empty placeholder value) —
    # the parameter name is real surface regardless of the recorded value.
    return [str(name) for name, _ in parse_qsl(query, keep_blank_values=True) if str(name).strip()]


def _endpoint_records(content: Any) -> list[Any]:
    """Extract the raw discovered-endpoint records from an observation payload.

    Handles the shapes emitted by the discovery adapters: ``endpoints``/``urls``/
    ``routes`` lists, katana's ``crawl.urls`` records, direct ``endpoint``/``url``
    keys, and the in-process crawler's ``APIEndpoint`` records (``url`` +
    ``method`` + ``parameters``). Never fabricates a URL from a missing value.
    """
    entries: list[Any] = []
    if isinstance(content, list):
        entries = content
    elif isinstance(content, dict):
        for key in ("endpoints", "urls", "routes"):
            entries.extend(_as_list(content.get(key)))
        crawl = content.get("crawl")
        if isinstance(crawl, dict):
            entries.extend(_as_list(crawl.get("urls")))
        # In-process javascript analysis payload: ``{"javascript": {"analyses": [
        #   {"endpoints": [{"url": ...}, ...], ...}, ...]}}``.
        javascript = content.get("javascript")
        if isinstance(javascript, dict):
            for analysis in _as_list(javascript.get("analyses")):
                if not isinstance(analysis, dict):
                    continue
                for key in ("endpoints", "routes"):
                    entries.extend(_as_list(analysis.get(key)))
        for key in ("endpoint", "url"):
            value = content.get(key)
            if value:
                entries.append(value)
    return entries


def _endpoint_urls(content: Any) -> list[str]:
    """Extract discovered endpoint URLs from an observation payload."""
    urls: list[str] = []
    for entry in _endpoint_records(content):
        if isinstance(entry, dict):
            value = entry.get("url") or entry.get("endpoint") or entry.get("path")
            if value:
                urls.append(str(value).strip())
        elif entry:
            urls.append(str(entry).strip())
    return [url for url in urls if url]


def _discovered_assets(content: dict[str, Any], asset_key: str) -> list[str]:
    """Extract the discovered asset names from a meaningful asset observation.

    Subdomain/host enumeration results carry the discovered names inside the
    content (``subdomains``, ``hosts``, ``names``, ``discoveries``); each
    discovered name becomes its own asset entry. When the content carries no
    names, the observation's own asset key is used.
    """
    names: list[str] = []
    for key in ("subdomains", "hosts", "domains", "names"):
        for item in _as_list(content.get(key)):
            value = _name_of(item)
            if value:
                names.append(value)
    if not names:
        for item in _as_list(
            content.get("discoveries")
            or [content.get("name") or content.get("host") or content.get("key") or asset_key]
        ):
            value = _name_of(item)
            if value:
                names.append(value)
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique


def _technology_names(content: dict[str, Any]) -> list[str]:
    """Extract distinct technology names from a technology observation.

    Adapters report technologies either as a flat ``name`` or as a nested
    list (``technologies``/``techs``) of strings or dicts carrying the
    canonical/raw name. Every distinct name becomes its own entity.
    """
    names: list[str] = []
    for item in _as_list(content.get("technologies") or content.get("techs") or [content.get("name")]):
        if isinstance(item, dict):
            name = str(
                item.get("canonical_name") or item.get("raw_name") or item.get("name") or item.get("product") or ""
            ).strip()
        else:
            name = str(item).strip()
        if name:
            names.append(name)
    unique: list[str] = []
    for name in names:
        if name not in unique:
            unique.append(name)
    return unique


def _service_entries(content: dict[str, Any], asset_key: str) -> list[tuple[str, str]]:
    """Extract the distinct discovered services from a service/port observation.

    Only open ports (and their fingerprints) become services. Closed/refused
    ports and host-reachability rows never do, and a named fingerprint
    supersedes its bare open-port entry so one service is not double-counted.
    """
    items: list[Any] = _as_list(content.get("observations") or [content])
    covered: set[str] = set()
    entries: dict[str, str] = {}

    def add(proto: str, port: object | None, service: str | None) -> None:
        proto = str(proto or "tcp")
        if port is not None and str(port).strip():
            if service:
                key = f"service:{asset_key}:{proto}:{port}:{service}"
                covered.add(f"{proto}:{port}")
            else:
                key = f"service:{asset_key}:{proto}:{port}"
            identity = f"{proto}:{port}:{service}" if service else f"{proto}:{port}"
        else:
            key = f"service:{asset_key}:{proto}:{service or 'unknown'}"
            identity = f"{proto}:{service or 'unknown'}"
        entries.setdefault(key, identity)

    for item in items:
        if not isinstance(item, dict) or not item:
            continue
        for port in _as_list(item.get("ports")):
            if port is not None and str(port).strip():
                add("tcp", port, None)
        itype = item.get("type")
        if itype == "host":
            continue
        if itype not in ("service", "port"):
            if "port" in item and ("service" in item or "name" in item):
                itype = "service"
            elif "port" in item:
                itype = "port"
            elif "service" in item or "name" in item:
                itype = "service"
            else:
                continue
        if itype == "service":
            service = str(item.get("service") or item.get("name") or "").strip() or None
            add(str(item.get("protocol") or "tcp"), item.get("port"), service)

    for item in items:
        if not isinstance(item, dict) or not item:
            continue
        itype = item.get("type")
        if itype == "host":
            continue
        if itype not in ("port",):
            if "port" in item and not ("service" in item or "name" in item):
                itype = "port"
            else:
                continue
        if item.get("state") and item.get("state") != "open":
            continue
        proto = str(item.get("protocol") or "tcp")
        port = item.get("port")
        if port is not None and str(port).strip():
            if f"{proto}:{port}" in covered:
                continue
            add(proto, port, None)
    return list(entries.items())


def _name_of(item: Any) -> str:
    """Return the string name of an asset item (string or ``{name, host, key}``)."""
    value = item.get("name") or item.get("host") or item.get("key") or "" if isinstance(item, dict) else item
    return str(value).strip()


def _coerce_candidate(value: Any) -> CandidateAction:
    """Coerce a candidate action from a dataclass or a JSON-safe mapping."""
    if isinstance(value, CandidateAction):
        return value
    if isinstance(value, dict):
        return CandidateAction(
            action_id=str(value.get("action_id", "")),
            capability=str(value.get("capability", "")),
            description=str(value.get("description", "")),
            tool_ids=tuple(value.get("tool_ids", []) or []),
            expected_information_gain=float(value.get("expected_information_gain", 0.0)),
            attack_surface_expansion=float(value.get("attack_surface_expansion", 0.0)),
            finding_validation_potential=float(value.get("finding_validation_potential", 0.0)),
            evidence_improvement=float(value.get("evidence_improvement", 0.0)),
            hypothesis_discrimination=float(value.get("hypothesis_discrimination", 0.0)),
            coverage_improvement=float(value.get("coverage_improvement", 0.0)),
            cost=float(value.get("cost", 0.1)),
            dependencies=tuple(value.get("dependencies", []) or []),
            reliability=float(value.get("reliability", 0.9)),
        )
    raise TypeError(f"cannot coerce candidate action from {type(value).__name__}")


#: Tool-report category names → canonical hypothesis categories.
_CATEGORY_MAP: dict[str, HypothesisType] = {
    "sql-injection": HypothesisType.INJECTION,
    "sql_injection": HypothesisType.INJECTION,
    "injection": HypothesisType.INJECTION,
    "sqli": HypothesisType.INJECTION,
    "xss": HypothesisType.XSS,
    "ssrf": HypothesisType.SSRF,
    "ssti": HypothesisType.SSTI,
    "xxe": HypothesisType.XXE,
    "lfi": HypothesisType.LFI,
    "rce": HypothesisType.RCE,
    "idor": HypothesisType.IDOR,
    "auth-bypass": HypothesisType.AUTHENTICATION_ISSUE,
    "auth_bypass": HypothesisType.AUTHENTICATION_ISSUE,
    "secret-exposure": HypothesisType.SECRET_EXPOSURE,
    "secret_exposure": HypothesisType.SECRET_EXPOSURE,
    "misconfiguration": HypothesisType.MISCONFIGURATION,
    "known-vulnerability": HypothesisType.KNOWN_VULNERABILITY,
}


def _coerce_category(category: HypothesisType | str) -> HypothesisType:
    """Coerce a category name into a canonical :class:`HypothesisType`."""
    if isinstance(category, HypothesisType):
        return category
    normalized = str(category).strip().lower()
    if normalized in _CATEGORY_MAP:
        return _CATEGORY_MAP[normalized]
    try:
        return HypothesisType(normalized)
    except ValueError:
        return HypothesisType.UNKNOWN_BEHAVIOR


#: Category → hypothesis priority. Evidence that implies a weakness (injection,
#: XSS, SSRF, ...) is high-value; discovery facts (asset/service) are low-value.
_HYPOTHESIS_PRIORITY: dict[str, float] = {
    "injection": 0.75,
    "xss": 0.75,
    "ssrf": 0.75,
    "ssti": 0.75,
    "xxe": 0.75,
    "lfi": 0.75,
    "rce": 0.80,
    "idor": 0.75,
    "api": 0.70,
    "graphql": 0.70,
    "secret_exposure": 0.70,
    "auth": 0.65,
    "authorization": 0.65,
    "technology": 0.55,
    "service": 0.55,
    "endpoint": 0.60,
    "parameter": 0.65,
    "asset": 0.35,
    "dns": 0.35,
    "unknown_behavior": 0.50,
}


def _priority_for_hypothesis(category: HypothesisType, observation_type: str) -> float:
    """Return an evidence-based priority for a hypothesis.

    A vulnerability-class hypothesis is high-value so it drives the next
    decision and blocks premature coverage-based stopping; a pure discovery
    fact (asset / service / technology) is deprioritized because it carries no
    weakness implication.
    """
    normalized_type = (observation_type or "").lower()
    if normalized_type == "vulnerability":
        return 0.75
    if normalized_type == "parameter":
        return 0.65
    if normalized_type in ("endpoint", "url", "api", "graphql"):
        return 0.60
    key = str(category.value if isinstance(category, HypothesisType) else category).lower()
    return _HYPOTHESIS_PRIORITY.get(key, 0.5)


def _elapsed_seconds(mission: OrchestratedMission) -> int:
    """Return the elapsed wall-clock seconds since mission creation."""
    try:
        from hunterx.shared.time import to_utc_datetime

        start = to_utc_datetime(mission.created_at)
        now = to_utc_datetime()
        return max(0, int((now - start).total_seconds()))
    except Exception:  # noqa: BLE001 - elapsed time is best-effort
        return mission.budget.time_used_seconds


def _promote_stage(current: str, incoming: str) -> str:
    """Promote a finding stage (never demote)."""
    order = [stage.value for stage in FindingStage]
    if current not in order:
        return incoming
    if order.index(incoming) > order.index(current):
        return incoming
    return current


#: Stop conditions that genuinely mean the mission objectives were met. These
#: are the only conditions that may set ``objectives_complete``; any other
#: terminal (budget/time exhausted, operator cancelled, unrecoverable failure,
#: blocked) leaves the objectives incomplete and is never reported as success.
_SUCCESS_STOP_CONDITIONS = frozenset(
    {
        StopCondition.OBJECTIVES_COMPLETE,
        StopCondition.COVERAGE_TARGET_ACHIEVED,
        StopCondition.HIGH_VALUE_HYPOTHESES_RESOLVED,
        StopCondition.FINDINGS_VALIDATED,
        StopCondition.ATTACK_SURFACE_EXHAUSTED,
    }
)

#: Orchestration phase derived from the Sprint 027 planning state. The phase is
#: workflow-driven — it reflects where the mission actually is, not what ran.
_PHASE_BY_PLANNING_STATE: dict[MissionState, MissionPhase] = {
    MissionState.CREATED: MissionPhase.TARGET_MODELING,
    MissionState.SCOPING: MissionPhase.TARGET_MODELING,
    MissionState.DISCOVERY: MissionPhase.RECONNAISSANCE,
    MissionState.ENUMERATION: MissionPhase.ENUMERATION,
    MissionState.MAPPING: MissionPhase.ATTACK_SURFACE_MAPPING,
    MissionState.ANALYSIS: MissionPhase.TECHNOLOGY_ANALYSIS,
    MissionState.HYPOTHESIS_GENERATION: MissionPhase.HYPOTHESIS_ANALYSIS,
    MissionState.VALIDATION: MissionPhase.ACTIVE_TESTING,
    MissionState.PROOF: MissionPhase.PROOF,
    MissionState.REASSESSMENT: MissionPhase.REASSESSMENT,
    MissionState.REPORTING: MissionPhase.REPORTING,
    MissionState.COMPLETED: MissionPhase.REPORTING,
    # A blocked mission is honestly shown as reassessment, never a stale phase.
    MissionState.BLOCKED: MissionPhase.REASSESSMENT,
}


#: Hypothesis states that are still open (not settled).
_OPEN_HYPOTHESIS_STATES = frozenset(
    {"proposed", "supported", "weakly_supported", "inconclusive", "novel_behavior"}
)


def _completion_gate_unmet(mission: OrchestratedMission) -> list[str]:
    """Return the objective completion-contract gates that are currently unmet.

    Best-effort (never raises): used to produce an explicit blocking reason.
    """
    try:
        from hunterx.domain.mission_orchestration.completion import contract_for_objective

        contract = contract_for_objective(
            getattr(getattr(mission, "mission", None), "objective", None),
            coverage_target=float(getattr(mission.policy, "coverage_target", 0.7) or 0.7),
        )
        pending_plan_work = any(
            not action.status.is_terminal for action in mission.mission.graph.actions.values()
        )
        return contract.evaluate(mission, pending_plan_work=pending_plan_work).unmet()
    except Exception:  # noqa: BLE001 - best-effort
        return []


def _ai_unavailable(mission: OrchestratedMission) -> bool:
    """Return ``True`` when the mission attempted AI but the provider was unusable.

    Distinguishes "AI unavailable/degraded" from any budget exhaustion: the flag
    reflects real AI invocation outcomes recorded on the reasoning trace and is
    independent of stop conditions.
    """
    attempted = False
    usable = 0
    for entry in mission.trace:
        content = dict(entry.content or {})
        if not content.get("ai_invoked"):
            continue
        attempted = True
        if content.get("ai_usable"):
            usable += 1
    return attempted and usable == 0


def _category_for_template(template: str) -> HypothesisType:
    """Map a vulnerability template/class name to a canonical hypothesis type."""
    name = str(template or "").strip().lower()
    if not name:
        return HypothesisType.UNKNOWN_BEHAVIOR
    if "xss" in name:
        return HypothesisType.XSS
    if "ssrf" in name:
        return HypothesisType.SSRF
    if "ssti" in name:
        return HypothesisType.SSTI
    if "xxe" in name:
        return HypothesisType.XXE
    if "lfi" in name or "rfi" in name or "path traversal" in name:
        return HypothesisType.LFI
    if "rce" in name or "code execution" in name or "command injection" in name:
        return HypothesisType.RCE
    if "sql" in name or "injection" in name:
        return HypothesisType.INJECTION
    if "idor" in name or "access control" in name:
        return HypothesisType.IDOR
    if "secret" in name or "credential" in name:
        return HypothesisType.SECRET_EXPOSURE
    if "auth" in name:
        return HypothesisType.AUTHENTICATION_ISSUE
    if "authorization" in name or "access" in name:
        return HypothesisType.AUTHORIZATION_ISSUE
    if "api" in name:
        return HypothesisType.API_SECURITY
    if "graphql" in name:
        return HypothesisType.GRAPHQL_SECURITY
    if "dependency" in name or "cve-" in name:
        return HypothesisType.DEPENDENCY_VULNERABILITY
    if "missing" in name or "misconfig" in name or "default" in name or "header" in name:
        return HypothesisType.MISCONFIGURATION
    return HypothesisType.UNKNOWN_BEHAVIOR


__all__ = ["MissionOrchestrator"]
