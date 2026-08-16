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

from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from hunterx.domain.adaptive_mission_planning.enums import (
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
        self.impact = impact or ImpactAnalysisEngine()
        self.cascade = cascade or FindingCascadeEngine()
        self._missions: dict[str, OrchestratedMission] = {}

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
        """
        mission = self.get(mission_id)
        if mission.outcome is not None:
            return mission
        condition = stop_condition or self.policy.evaluate_stop(mission) or StopCondition.OBJECTIVES_COMPLETE
        if self.planning is not None:
            self._advance_to_completed(mission_id)
        mission.current_phase = MissionPhase.REPORTING
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
        mission.outcome = MissionOutcome(
            mission_id=mission_id,
            phase=mission.current_phase.value,
            objectives_complete=not mission.context.remaining_objectives,
            findings_validated=validated,
            findings_report_ready=report_ready,
            hypotheses_resolved=resolved,
            attack_paths_discovered=len(mission.context.attack_paths),
            coverage_ratio=mission.coverage_ratio(),
            executions_used=mission.budget.executions_used,
            stop_condition=condition.value,
        )
        self.telemetry.record(mission)
        self._trace_mission(mission, MissionEventType.MISSION_COMPLETED, stop_condition=condition.value)
        return mission

    # -- observation intake --------------------------------------------------

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
        """Attach the hypothesis that explains a candidate finding.

        The candidate finding and the hypothesis are both derived from the same
        observation; recording ``hypothesis_id`` on the finding lets the runner
        promote the finding only when its explaining hypothesis is validated —
        a tool output is never a vulnerability by itself.
        """
        observation_id = observation.observation_id
        hypothesis = next(
            (
                hypothesis
                for hypothesis in mission.hypotheses
                if observation_id and observation_id in hypothesis.supporting_evidence
            ),
            None,
        )
        if hypothesis is None:
            return
        for finding in mission.context.findings:
            if finding.get("stage") != "candidate":
                continue
            refs = finding.get("evidence_refs") or ()
            if observation_id not in refs:
                continue
            if finding.get("hypothesis_id") in (None, ""):
                finding["hypothesis_id"] = hypothesis.hypothesis_id

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

    def _candidates_from_plan(self, mission: OrchestratedMission) -> tuple[CandidateAction, ...]:
        """Build candidate actions from the adaptive mission's ready actions.

        An action explicitly bound to an open hypothesis (the replanning layer
        links a NEW_HYPOTHESIS_CREATED validation node to its hypothesis) is
        marked with ``hypothesis_id`` so the decision engine can rank evidence-
        driven probes above unrelated work.
        """
        if self.planning is None:
            return ()
        ready = self.planning.next_parallel_wave(mission.mission_id)
        candidates: list[CandidateAction] = []
        for action in ready:
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
        """Register (or update) a finding on the mission context."""
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
        mission.context.findings.append(finding)
        self._trace_mission(mission, MissionEventType.MISSION_FINDING_CREATED, finding_id=finding["finding_id"])
        return finding

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
        statement = ""
        category: HypothesisType = HypothesisType.UNKNOWN_BEHAVIOR
        if observation.observation_type == "vulnerability":
            for finding in _as_list(content.get("content") or content):
                if not isinstance(finding, dict) or not finding:
                    continue
                template = _template_of(finding) or "unknown"
                statement = f"{asset_key} may be affected by {template}"
                category = _category_for_template(template)
                if statement:
                    break
        elif observation.observation_type in ("technology", "tech"):
            name = str(content.get("name") or "").strip()
            if name:
                statement = f"{asset_key} runs technology {name}"
        elif observation.observation_type in ("service", "port"):
            service = str(content.get("service") or content.get("name") or "").strip()
            if service:
                statement = f"{asset_key} exposes service {service}"
        elif observation.observation_type in ("endpoint", "url", "api", "graphql", "javascript", "route"):
            for endpoint in _as_list(content.get("endpoints") or content.get("urls") or content.get("routes") or [content.get("endpoint") or content.get("url")]):
                endpoint = str(endpoint).strip()
                if endpoint:
                    statement = f"{endpoint} is a reachable endpoint of the target"
                    break
        elif observation.observation_type in ("asset", "subdomain", "host", "hostname", "domain") and asset_key and asset_key != "target":
            statement = f"{asset_key} is part of the target's attack surface"
        if not statement:
            return
            return
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
                priority=_priority_for_hypothesis(category, observation.observation_type),
                proposed_by=f"observation:{observation.tool_id or 'tool'}",
                behavior_class=behavior_class,
                provenance_hint={
                    "observation_id": observation.observation_id,
                    "observation_type": observation.observation_type,
                    "asset_key": asset_key,
                },
            )
        except Exception:  # noqa: BLE001 - hypothesis creation is best-effort
            return

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
            endpoints = [
                str(endpoint)
                for endpoint in _as_list(content.get("endpoints") or content.get("urls") or content.get("routes") or [content.get("endpoint") or content.get("url")])
                if str(endpoint).strip()
            ]
            for entry in _as_list(content.get("technologies")):
                if not isinstance(entry, dict):
                    continue
                url = str(entry.get("asset") or entry.get("url") or "").strip()
                if url:
                    endpoints.append(url)
            for endpoint in endpoints:
                if not str(endpoint).strip():
                    continue
                mission.context.endpoints[f"endpoint:{endpoint}"] = {"key": str(endpoint), "content": content}
        elif observation_type == "parameter":
            parameters = [
                str(parameter)
                for parameter in _as_list(content.get("parameters") or [content.get("parameter")])
                if str(parameter).strip()
            ]
            for parameter in parameters:
                mission.context.parameters[f"param:{asset_key}:{parameter}"] = {
                    "key": asset_key,
                    "parameter": str(parameter),
                }
        elif observation_type == "vulnerability":
            for finding in _as_list(content.get("content") or content):
                if not isinstance(finding, dict) or not finding:
                    continue
                template = _template_of(finding) or "unknown"
                self.register_finding(
                    mission.mission_id,
                    vulnerability_class=template,
                    asset_key=asset_key or mission.context.target_id or "target",
                    target=mission.context.target_id or "",
                    severity=str(finding.get("severity") or "info"),
                    tool=observation.tool_id or "",
                    stage=FindingStage.CANDIDATE,
                    evidence_refs=(observation.evidence_ref or observation.observation_id,),
                    description=f"candidate from {observation.tool_id or 'tool'} observation {observation.observation_id}",
                )

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
    MissionState.VALIDATION: MissionPhase.VALIDATION,
    MissionState.PROOF: MissionPhase.PROOF,
    MissionState.REASSESSMENT: MissionPhase.REASSESSMENT,
    MissionState.REPORTING: MissionPhase.REPORTING,
    MissionState.COMPLETED: MissionPhase.REPORTING,
}


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
    if "authorization" in name:
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
