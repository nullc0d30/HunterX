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
        """Finalize a mission and record its outcome."""
        mission = self.get(mission_id)
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
    ) -> MissionHypothesis:
        """Create and register a hypothesis (idempotent by statement)."""
        mission = self.get(mission_id)
        for existing in mission.hypotheses:
            if existing.statement == statement:
                return existing
        category_enum = _coerce_category(category)
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
        """Build candidate actions from the adaptive mission's ready actions."""
        if self.planning is None:
            return ()
        ready = self.planning.next_parallel_wave(mission.mission_id)
        candidates: list[CandidateAction] = []
        for action in ready:
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
                    hypothesis_discrimination=0.2 if action.hypothesis_id else 0.1,
                    coverage_improvement=0.3,
                    cost=action.cost,
                    dependencies=action.depends_on,
                    reliability=max(0.5, 1.0 - action.risk),
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

    def _populate_context(self, mission: OrchestratedMission, observation: MissionObservation) -> None:
        """Update the target-centric context from a normalized observation.

        The observation content is treated as data, never as instructions. The
        context maps are keyed by (type:key) so the same target keeps a single
        authoritative record per discovered item.
        """
        content = observation.content
        asset_key = observation.asset_key or str(content.get("key", ""))
        observation_type = observation.observation_type

        if observation_type in ("asset", "subdomain", "host", "hostname", "domain"):
            mission.context.assets[f"asset:{asset_key}"] = {"key": asset_key, "content": content}
        elif observation_type in ("technology", "tech"):
            mission.context.technologies[f"tech:{asset_key}:{content.get('name', content)}"] = {
                "key": asset_key,
                "content": content,
            }
        elif observation_type in ("service", "port"):
            mission.context.services[f"service:{asset_key}"] = {"key": asset_key, "content": content}
        elif observation_type in ("endpoint", "url", "api", "graphql", "javascript", "route"):
            for endpoint in _as_list(content.get("endpoints") or content.get("urls") or content.get("routes") or [content.get("endpoint") or content.get("url") or asset_key]):
                mission.context.endpoints[f"endpoint:{endpoint}"] = {"key": str(endpoint), "content": content}
        elif observation_type == "parameter":
            for parameter in _as_list(content.get("parameters") or [content.get("parameter")]):
                mission.context.parameters[f"param:{asset_key}:{parameter}"] = {
                    "key": asset_key,
                    "parameter": str(parameter),
                }
        elif observation_type == "vulnerability":
            for finding in _as_list(content.get("content") or content):
                if isinstance(finding, dict):
                    template = finding.get("template") or finding.get("class") or "unknown"
                    mission.context.assets[f"finding:{asset_key}:{template}"] = {
                        "key": asset_key,
                        "vulnerability_class": str(template),
                        "content": finding,
                    }

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


__all__ = ["MissionOrchestrator"]
