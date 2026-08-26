# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration — use-case services.

``MissionOrchestrationService`` bridges the :class:`MissionOrchestrationEngine`
(the Sprint 032 adaptive loop) to the TIDB system-of-record: it persists
normalized mission entities (missions, runs, phases, actions, decisions,
hypotheses, branches, checkpoints, policies, objectives, coverage, timelines,
observations, negative evidence, baselines, reasoning trace, telemetry, impact)
and publishes ``mission.*`` events.

``MissionOrchestrationQueryService`` reads the canonical mission views back:
state, timeline, decisions, hypotheses, findings, attack paths, coverage and
tool executions.
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import Any

from hunterx.domain.entities.tidb.mission_orchestration import (
    MissionActionRecord,
    MissionBaselineRecord,
    MissionBranchRecord,
    MissionCheckpointRecord,
    MissionCoverageRecord,
    MissionDecisionRecord,
    MissionHypothesisRecord,
    MissionImpactRecord,
    MissionNegativeRecord,
    MissionObjectiveRecord,
    MissionObservationRecord,
    MissionOrchestrationRecord,
    MissionPolicyRecord,
    MissionRunRecord,
    MissionTelemetryRecord,
    MissionTimelineRecord,
)
from hunterx.domain.exceptions.adaptive_mission_planning import AdaptiveMissionNotFoundError
from hunterx.domain.mission_orchestration.enums import StrategyKind
from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.ports.messaging import EventBusPort
from hunterx.domain.ports.tidb_repositories import TidbRepositoryFactory
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine


class MissionOrchestrationService:
    """Orchestrate the autonomous mission layer against the TIDB."""

    def __init__(
        self,
        *,
        engine: MissionOrchestrationEngine | None = None,
        stores: TidbRepositoryFactory | None = None,
        event_bus: EventBusPort | None = None,
        resource_config: Any | None = None,
    ) -> None:
        self._engine = engine or MissionOrchestrationEngine()
        self._stores = stores
        self._event_bus = event_bus
        #: Bounded in-memory mission state (persisted copies stay durable). When
        #: wired, every persistence point trims the in-memory aggregate to the
        #: configured caps so an autonomous mission can never accumulate
        #: unbounded RAM (see ``hunterx.resource.bounds``).
        self._resource_config = resource_config

    @property
    def engine(self) -> MissionOrchestrationEngine:
        """Return the underlying orchestration engine."""
        return self._engine

    # -- lifecycle ----------------------------------------------------------

    def create_mission(
        self,
        *,
        objective: str = "full_security_assessment",
        mode: str = "balanced",
        target: str = "",
        included_targets: tuple[str, ...] = (),
        excluded_assets: tuple[str, ...] = (),
        strategy: str = "adaptive",
        tenant: str = "",
        authorization_context: str = "default",
        safety_ceiling: str = "low_impact_active",
        resource_budget: int = 1000,
        time_budget_seconds: int = 0,
        coverage_target: float = 0.7,
        max_concurrency: int = 4,
    ) -> OrchestratedMission:
        """Create an orchestrated mission with its initial adaptive plan.

        Budget semantics: ``time_budget_seconds=0`` means *unlimited* wall-clock
        budget and ``resource_budget=0`` permits no executions. Negative values
        are rejected at configuration time so a malformed budget can never
        silently behave as an exhausted (or unlimited) budget at runtime.
        """
        if resource_budget < 0:
            raise ValueError("resource_budget must be >= 0 (0 permits no executions)")
        if time_budget_seconds < 0:
            raise ValueError("time_budget_seconds must be >= 0 (0 means unlimited)")
        mission = self._engine.create_mission(
            objective=objective,
            mode=mode,
            target=target,
            tenant=tenant,
            authorization_context=authorization_context,
            safety_ceiling=safety_ceiling,
            strategy=_strategy_enum(strategy),
        )
        mission.policy = dataclasses.replace(
            mission.policy,
            resource_budget=resource_budget,
            time_budget_seconds=time_budget_seconds,
            coverage_target=coverage_target,
            max_concurrency=max_concurrency,
        )
        mission.budget = dataclasses.replace(
            mission.budget,
            executions_budget=resource_budget,
            time_budget_seconds=time_budget_seconds,
            max_concurrency=max_concurrency,
        )
        if included_targets or excluded_assets:
            mission.context.scope = _with_scope(
                mission.context.scope,
                included_targets=included_targets,
                excluded_assets=excluded_assets,
                target=target,
            )
        self._persist_mission(mission)
        self._persist_policy(mission)
        self._persist_objectives(mission)
        self._publish(
            "mission.started",
            {
                "mission_id": mission.mission_id,
                "objective": mission.policy.objective_name,
                "target": target,
                "strategy": mission.policy.strategy.value,
            },
        )
        return mission

    def get(self, mission_id: str) -> OrchestratedMission:
        """Return an orchestrated mission by id.

        Falls back to hydrating a persisted mission from the TIDB
        system-of-record when the in-memory store does not hold it (for example
        after a process restart or across separate CLI invocations).
        """
        try:
            return self._engine.get(mission_id)
        except AdaptiveMissionNotFoundError:
            restored = self._restore_mission(mission_id)
            if restored is None:
                raise
            return restored

    def status(self, mission_id: str) -> dict[str, Any]:
        """Return the JSON-safe mission status."""
        return self.get(mission_id).to_dict()

    def list_missions(self, *, limit: int = 100, offset: int = 0) -> list[OrchestratedMission]:
        """Return registered orchestrated missions."""
        return self._engine.missions()[offset : offset + limit]

    def start(self, mission_id: str) -> dict[str, Any]:
        """Start a mission run."""
        self.get(mission_id)
        mission = self._engine.start(mission_id)
        self._persist_mission(mission)
        self._persist_runs(mission)
        self._publish("mission.run.started", {"mission_id": mission_id})
        return mission.to_dict()

    def pause(self, mission_id: str) -> dict[str, Any]:
        """Pause a mission."""
        self.get(mission_id)
        mission = self._engine.pause(mission_id)
        self._persist_mission(mission)
        self._publish("mission.paused", {"mission_id": mission_id})
        return mission.to_dict()

    def resume(self, mission_id: str) -> dict[str, Any]:
        """Resume a mission."""
        self.get(mission_id)
        mission = self._engine.resume(mission_id)
        self._persist_mission(mission)
        self._publish("mission.resumed", {"mission_id": mission_id})
        return mission.to_dict()

    def cancel(self, mission_id: str) -> dict[str, Any]:
        """Cancel a mission."""
        self.get(mission_id)
        mission = self._engine.cancel(mission_id)
        self._persist_mission(mission)
        self._publish("mission.completed", {"mission_id": mission_id, "stop": "operator_cancelled"})
        return mission.to_dict()

    def finalize(self, mission_id: str, *, stop_condition: str | None = None) -> dict[str, Any]:
        """Finalize a mission and record its outcome.

        ``stop_condition`` optionally forces the terminal reason; otherwise the
        orchestrator derives the truthful stop (never claiming success while
        the objectives are incomplete).
        """
        from hunterx.domain.mission_orchestration.enums import StopCondition

        self.get(mission_id)
        resolved: StopCondition | None = None
        if stop_condition:
            resolved = StopCondition(stop_condition)
        mission = self._engine.finalize(mission_id, stop_condition=resolved)
        self._persist_mission(mission)
        self._persist_runs(mission)
        self._persist_telemetry(mission)
        self._publish(
            "mission.completed",
            {"mission_id": mission_id, "stop": mission.outcome.stop_condition if mission.outcome else ""},
        )
        return mission.to_dict()

    def sync_phase(self, mission_id: str) -> str:
        """Synchronize the orchestration phase from the planning state."""
        mission = self._engine.sync_phase(mission_id)
        return mission.value

    # -- reasoning loop -----------------------------------------------------

    def record_probe(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Record a targeted differential probe execution as an observation."""
        observation = self._engine.record_probe(mission_id, **kwargs)
        self._persist_observation(mission_id, observation)
        self._persist_mission(self._engine.get(mission_id))
        self._publish(
            "mission.probe.recorded",
            {
                "mission_id": mission_id,
                "observation_id": observation.observation_id,
                "vulnerability_class": str(kwargs.get("vulnerability_class") or ""),
                "supported": bool(kwargs.get("supported", False)),
            },
        )
        return observation.to_dict()

    def record_attack_paths(self, mission_id: str) -> list[dict[str, Any]]:
        """Record attack paths derived from the discovered attack surface."""
        paths = self._engine.record_attack_paths(mission_id)
        self._persist_mission(self._engine.get(mission_id))
        return paths

    def ingest_result(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Ingest and normalize a tool result."""
        observation = self._engine.ingest_result(mission_id, **kwargs)
        self._persist_observation(mission_id, observation)
        self._persist_mission(self._engine.get(mission_id))
        self._publish(
            "mission.observation.created",
            {"mission_id": mission_id, "observation_id": observation.observation_id},
        )
        return observation.to_dict()

    def add_hypothesis(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Create a hypothesis."""
        hypothesis = self._engine.add_hypothesis(mission_id, **kwargs)
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.created",
            {"mission_id": mission_id, "hypothesis_id": hypothesis.hypothesis_id},
        )
        return hypothesis.to_dict()

    def update_hypothesis(self, mission_id: str, hypothesis_id: str, **kwargs: Any) -> dict[str, Any]:
        """Advance a hypothesis with new evidence."""
        hypothesis = self._engine.update_hypothesis(mission_id, hypothesis_id, **kwargs)
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.updated",
            {"mission_id": mission_id, "hypothesis_id": hypothesis_id, "state": hypothesis.state.value},
        )
        return hypothesis.to_dict()

    def verify_hypothesis(self, mission_id: str, hypothesis_id: str, **kwargs: Any) -> dict[str, Any]:
        """Verify a supported hypothesis (promotes to VALIDATED when reproducible)."""
        hypothesis = self._engine.verify_hypothesis(mission_id, hypothesis_id, **kwargs)
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.updated",
            {"mission_id": mission_id, "hypothesis_id": hypothesis_id, "state": hypothesis.state.value},
        )
        return hypothesis.to_dict()

    def refute_hypothesis(self, mission_id: str, hypothesis_id: str, **kwargs: Any) -> dict[str, Any]:
        """Refute a hypothesis whose class-specific probe found no signal."""
        hypothesis = self._engine.refute_hypothesis(mission_id, hypothesis_id, **kwargs)
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.updated",
            {"mission_id": mission_id, "hypothesis_id": hypothesis_id, "state": hypothesis.state.value},
        )
        return hypothesis.to_dict()

    def defer_hypothesis(self, mission_id: str, hypothesis_id: str, *, reason: str) -> dict[str, Any] | None:
        """Explicitly classify an open hypothesis as deferred with a recorded reason.

        A deferred hypothesis is acknowledged but not tested now (capability
        unavailable, budget priority, out of scope). It is reported as partial/
        blocked, never as settled evidence or as a complete assessment.
        """
        self._engine.defer_hypothesis(mission_id, hypothesis_id, reason=reason)
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            return None
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.updated",
            {"mission_id": mission_id, "hypothesis_id": hypothesis_id, "state": "deferred", "reason": reason},
        )
        return hypothesis.to_dict()

    def block_hypothesis(self, mission_id: str, hypothesis_id: str, *, reason: str) -> dict[str, Any] | None:
        """Explicitly classify an actionable hypothesis as blocked with a reason.

        A blocked hypothesis is actionable but cannot be probed under the
        current policy (capability unavailable / target not probeable).
        """
        self._engine.block_hypothesis(mission_id, hypothesis_id, reason=reason)
        mission = self.get(mission_id)
        hypothesis = mission.hypothesis(hypothesis_id)
        if hypothesis is None:
            return None
        self._persist_hypothesis(mission_id, hypothesis)
        self._publish(
            "mission.hypothesis.updated",
            {"mission_id": mission_id, "hypothesis_id": hypothesis_id, "state": "blocked", "reason": reason},
        )
        return hypothesis.to_dict()

    def classify_open_hypotheses(
        self,
        mission_id: str,
        *,
        reason: str = "no runnable action under current policy/capability availability",
    ) -> int:
        """Classify non-actionable open hypotheses as deferred (best-effort).

        Returns the number of hypotheses classified.
        """
        classified = self._engine.classify_open_hypotheses(mission_id, reason=reason)
        mission = self.get(mission_id)
        self._persist_mission(mission)
        return classified

    def decide_next(self, mission_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Select the next action by expected information gain."""
        decision = self._engine.decide_next(mission_id, **kwargs)
        if decision is None:
            return None
        self._persist_decision(mission_id, decision)
        self._publish(
            "mission.action.selected",
            {"mission_id": mission_id, "action_id": decision.next_action, "tool_id": decision.tool_id},
        )
        return decision.to_dict()

    def explain_next(self, mission_id: str) -> dict[str, Any]:
        """Explain the next best action."""
        return self._engine.explain_next(mission_id)

    def record_ai_trace(self, mission_id: str, *, decision_id: str = "", **trace: Any) -> None:
        """Record an AI-invocation provenance trace entry for a decision.

        Best-effort observability: AI involvement (invoked, latency, suggestion,
        acceptance) is recorded on the mission reasoning trace without affecting
        the decision or the mission state.
        """
        with contextlib.suppress(Exception):  # provenance recording is best-effort
            self._engine.record_ai_trace(mission_id, decision_id=decision_id, **trace)

    def record_ai_decision(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Persist an AI Hunt Director decision as a first-class decision record.

        Marked ``ai_assisted`` and carrying provider/model provenance so the
        durable decision log proves AI direction (never credentials).
        """
        decision = self._engine.orchestrator.record_ai_decision(mission_id, **kwargs)
        self._persist_decision(mission_id, decision)
        self._persist_mission(self._engine.get(mission_id))
        return decision.to_dict()

    def explain_decision(self, mission_id: str, decision_id: str = "") -> dict[str, Any] | None:
        """Return an explainable decision record."""
        return self._engine.explain_decision(mission_id, decision_id)

    def record_negative(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Record bounded negative evidence."""
        record = self._engine.record_negative(mission_id, **kwargs)
        self._persist_negative(mission_id, record)
        return record.to_dict()

    def record_coverage(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Record a coverage cell and return the coverage summary."""
        self._engine.record_coverage(mission_id, **kwargs)
        mission = self._engine.get(mission_id)
        self._persist_coverage(mission)
        return self._engine.coverage_summary(mission_id)

    def coverage(self, mission_id: str) -> dict[str, Any]:
        """Return the mission coverage summary."""
        return self._engine.coverage_summary(mission_id)

    def knowledge_gaps(self, mission_id: str) -> list[dict[str, Any]]:
        """Return ranked knowledge gaps."""
        return [gap.to_dict() for gap in self._engine.knowledge_gaps(mission_id)]

    def capture_baseline(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Capture a baseline observation."""
        baseline = self._engine.capture_baseline(mission_id, **kwargs)
        self._persist_baseline(mission_id, baseline)
        return baseline.to_dict()

    def differential_test(self, mission_id: str, **kwargs: Any) -> dict[str, Any] | None:
        """Run a differential test."""
        result = self._engine.differential_test(mission_id, **kwargs)
        return result.to_dict() if result is not None else None

    def fork_branch(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Open a mission branch."""
        branch = self._engine.fork_branch(mission_id, **kwargs)
        self._persist_branch(mission_id, branch)
        self._publish("mission.branch.created", {"mission_id": mission_id, "branch_id": branch.branch_id})
        return branch.to_dict()

    def resolve_branch(self, mission_id: str, branch_id: str, **kwargs: Any) -> dict[str, Any]:
        """Resolve a mission branch."""
        branch = self._engine.resolve_branch(mission_id, branch_id, **kwargs)
        self._persist_branch(mission_id, branch)
        return branch.to_dict()

    def compute_confidence(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Compute an evidence-driven confidence score."""
        return self._engine.compute_confidence(mission_id, **kwargs).to_dict()

    def analyze_impact(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Analyze impact for a validated finding."""
        analysis = self._engine.analyze_impact(mission_id, **kwargs)
        self._persist_impact(mission_id, analysis)
        return analysis.to_dict()

    def cascade_findings(self, mission_id: str) -> list[dict[str, Any]]:
        """Open follow-on hypotheses from validated findings (reassessment)."""
        hypotheses = self._engine.cascade_findings(mission_id)
        for hypothesis in hypotheses:
            self._persist_hypothesis(mission_id, hypothesis)
        return [hypothesis.to_dict() for hypothesis in hypotheses]

    def register_finding(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Register (or update) a finding on the mission."""
        finding = self._engine.register_finding(mission_id, **kwargs)
        self._publish(
            "mission.finding.created",
            {"mission_id": mission_id, "finding_id": finding.get("finding_id")},
        )
        return finding

    def start_novel(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Open a novel-behavior investigation record."""
        return self._engine.start_novel(mission_id, **kwargs).to_dict()

    def advance_novel(self, mission_id: str, record_id: str, **kwargs: Any) -> dict[str, Any]:
        """Advance a novel-behavior record through the experiment loop."""
        return self._engine.advance_novel(mission_id, record_id, **kwargs).to_dict()

    # -- checkpoints --------------------------------------------------------

    def checkpoint(self, mission_id: str, *, label: str = "") -> dict[str, Any]:
        """Snapshot the full resumable mission state."""
        snapshot = self._engine.checkpoint(mission_id, label=label)
        self._persist_checkpoint(mission_id, snapshot)
        self._publish(
            "mission.checkpoint.created",
            {"mission_id": mission_id, "checkpoint_id": snapshot["checkpoint_id"]},
        )
        return snapshot

    def resume_from_checkpoint(self, mission_id: str, checkpoint_id: str) -> dict[str, Any]:
        """Restore a mission from a persisted checkpoint."""
        checkpoint = self._load_checkpoint(mission_id, checkpoint_id)
        mission = self._engine.resume_from_checkpoint(mission_id, checkpoint)
        self._persist_mission(mission)
        self._publish("mission.resumed", {"mission_id": mission_id, "checkpoint_id": checkpoint_id})
        return mission.to_dict()

    def stop_condition(self, mission_id: str) -> dict[str, Any]:
        """Evaluate the mission stop conditions."""
        condition = self._engine.stop_condition(mission_id)
        return {"mission_id": mission_id, "stop_condition": condition.value if condition else None}

    def telemetry(self, mission_id: str) -> dict[str, Any]:
        """Return the latest telemetry snapshot."""
        return self._engine.telemetry(mission_id)

    def record_telemetry(self, mission_id: str) -> dict[str, Any]:
        """Compute and persist a telemetry snapshot for the mission.

        Snapshots are normally recorded at checkpoint/finalize time; the
        execution runner calls this after every cycle so live missions expose
        telemetry (tool executions, utilization, failure counts) while they
        run.
        """
        mission = self._engine.get(mission_id)
        self._engine.orchestrator.telemetry.record(mission)
        self._persist_mission(mission)
        latest = mission.last_telemetry()
        return latest.to_dict() if latest else {}

    # -- persistence helpers -------------------------------------------------

    def _restore_mission(self, mission_id: str) -> OrchestratedMission | None:
        """Hydrate an orchestrated mission from the TIDB system-of-record.

        Returns ``None`` when no persisted mission matches (the caller then
        re-raises :class:`AdaptiveMissionNotFoundError`).
        """
        if self._stores is None:
            return None
        repo = self._stores.repository_for(MissionOrchestrationRecord)
        record = repo.get(mission_id)
        if record is None:
            return None
        mission = _mission_from_record(record)
        return self._engine.restore(mission)

    def _persist_mission(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionOrchestrationRecord)
        repo.save(
            MissionOrchestrationRecord(
                id=mission.mission_id,
                mission_id=mission.mission_id,
                objective=mission.policy.objective_name,
                mode=mission.mission.mode.value,
                state=mission.mission.state.value,
                strategy=mission.policy.strategy.value,
                current_phase=mission.current_phase.value,
                target=mission.context.target_id,
                tenant=mission.mission.tenant,
                authorization_context=mission.mission.authorization_context,
                policy=mission.policy.to_dict(),
                budget=mission.budget.to_dict(),
                coverage_ratio=mission.coverage_ratio(),
                outcome=mission.outcome.to_dict() if mission.outcome else None,
            )
        )
        self._apply_bounds(mission)

    def _apply_bounds(self, mission: OrchestratedMission) -> None:
        """Trim the in-memory mission aggregate to the configured resource caps.

        Only the in-memory working set is bounded — the TIDB persisted records
        remain the durable mission state. Runs in constant time while the
        aggregate is within its caps (the common case).
        """
        config = self._resource_config
        if config is None or mission is None:
            return
        from hunterx.resource.bounds import apply_mission_bounds

        with contextlib.suppress(Exception):  # bounds are best-effort memory hygiene
            apply_mission_bounds(mission, config)

    def _persist_runs(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionRunRecord)
        for run in mission.runs:
            repo.save(
                MissionRunRecord(
                    id=run.run_id,
                    run_id=run.run_id,
                    mission_id=mission.mission_id,
                    status=run.status.value,
                    started_at=run.started_at,
                    finished_at=run.finished_at,
                    resumed_from_run_id=run.resumed_from_run_id,
                    checkpoint_id=run.checkpoint_id,
                    last_action_id=run.last_action_id,
                    error=run.error,
                )
            )

    def _persist_policy(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionPolicyRecord)
        repo.save(
            MissionPolicyRecord(
                id=mission.policy.policy_id,
                policy_id=mission.policy.policy_id,
                mission_id=mission.mission_id,
                objective_name=mission.policy.objective_name,
                strategy=mission.policy.strategy.value,
                allowed_techniques=list(mission.policy.allowed_techniques),
                resource_budget=mission.policy.resource_budget,
                time_budget_seconds=mission.policy.time_budget_seconds,
                validation_depth=mission.policy.validation_depth,
                proof_depth=mission.policy.proof_depth,
                coverage_target=mission.policy.coverage_target,
                stop_conditions=[condition.value for condition in mission.policy.stop_conditions],
                max_concurrency=mission.policy.max_concurrency,
                rate_limit_per_minute=mission.policy.rate_limit_per_minute,
            )
        )

    def _persist_objectives(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionObjectiveRecord)
        for objective in mission.context.current_objectives:
            repo.save(
                MissionObjectiveRecord(
                    id=_stable_id("objective", mission.mission_id, objective),
                    record_id=objective,
                    mission_id=mission.mission_id,
                    objective=objective,
                    status="remaining",
                )
            )

    def _persist_observation(self, mission_id: str, observation: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionObservationRecord)
        repo.save(
            MissionObservationRecord(
                id=observation.observation_id,
                observation_id=observation.observation_id,
                mission_id=mission_id,
                action_id=observation.action_id,
                tool_id=observation.tool_id,
                tool_version=observation.tool_version,
                asset_key=observation.asset_key,
                observation_type=observation.observation_type,
                content=observation.content,
                evidence_ref=observation.evidence_ref,
                confidence=observation.confidence,
                provenance=observation.provenance,
            )
        )

    def _persist_hypothesis(self, mission_id: str, hypothesis: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionHypothesisRecord)
        repo.save(
            MissionHypothesisRecord(
                id=hypothesis.hypothesis_id,
                hypothesis_id=hypothesis.hypothesis_id,
                mission_id=mission_id,
                statement=hypothesis.statement,
                category=hypothesis.category.value if hasattr(hypothesis.category, "value") else str(hypothesis.category),
                state=hypothesis.state.value,
                behavior_class=hypothesis.behavior_class.value,
                supporting_evidence=list(hypothesis.supporting_evidence),
                contradicting_evidence=list(hypothesis.contradicting_evidence),
                tested_actions=list(hypothesis.tested_actions),
                confidence=hypothesis.confidence,
                priority=hypothesis.priority,
                validation_strategy=hypothesis.validation_strategy,
                proof_strategy=hypothesis.proof_strategy,
                proposed_by=hypothesis.proposed_by,
                provenance=hypothesis.provenance,
            )
        )

    def _persist_decision(self, mission_id: str, decision: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionDecisionRecord)
        repo.save(
            MissionDecisionRecord(
                id=decision.decision_id,
                decision_id=decision.decision_id,
                mission_id=mission_id,
                next_action=decision.next_action,
                capability=decision.capability,
                tool_id=decision.tool_id,
                reason=decision.reason,
                expected_result=decision.expected_result,
                priority=decision.priority,
                dependencies=list(decision.dependencies),
                alternatives=[list(pair) for pair in decision.alternatives],
                information_gain=decision.information_gain,
                factors=decision.factors,
                ai_assisted=decision.ai_assisted,
                latency_ms=decision.latency_ms,
            )
        )

    def _persist_negative(self, mission_id: str, record: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionNegativeRecord)
        repo.save(
            MissionNegativeRecord(
                id=record.record_id,
                record_id=record.record_id,
                mission_id=mission_id,
                asset_key=record.asset_key,
                capability=record.capability,
                kind=record.kind.value,
                tool_id=record.tool_id,
                tool_version=record.tool_version,
                input_hash=record.input_hash,
                outcome=record.outcome,
                conditions=record.conditions,
                notes=record.notes,
            )
        )

    def _persist_coverage(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionCoverageRecord)
        for cell in mission.coverage_cells():
            repo.save(
                MissionCoverageRecord(
                    id=_stable_id("coverage", mission.mission_id, cell.cell_key),
                    cell_key=cell.cell_key,
                    mission_id=mission.mission_id,
                    asset_key=cell.asset_key,
                    capability=cell.capability,
                    state=cell.state.value,
                    tool_id=cell.tool_id,
                    confidence=cell.confidence,
                    evidence_refs=list(cell.evidence_refs),
                    tested_at=cell.tested_at,
                    notes=cell.notes,
                )
            )

    def _persist_baseline(self, mission_id: str, baseline: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionBaselineRecord)
        repo.save(
            MissionBaselineRecord(
                id=_stable_id("baseline", mission_id, baseline.baseline_id),
                baseline_id=baseline.baseline_id,
                mission_id=mission_id,
                asset_key=baseline.asset_key,
                request_fingerprint=baseline.request_fingerprint,
                status_code=baseline.status_code,
                headers=baseline.headers,
                content_length=baseline.content_length,
                body_hash=baseline.body_hash,
                timing_ms=baseline.timing_ms,
                parameters=baseline.parameters,
                provenance=baseline.provenance,
            )
        )

    def _persist_branch(self, mission_id: str, branch: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionBranchRecord)
        repo.save(
            MissionBranchRecord(
                id=branch.branch_id,
                branch_id=branch.branch_id,
                mission_id=mission_id,
                parent_branch_id=branch.parent_branch_id,
                hypothesis_id=branch.hypothesis_id,
                rationale=branch.rationale,
                state=branch.state,
                actions=list(branch.actions),
                evidence_refs=list(branch.evidence_refs),
                cost=branch.cost,
                priority=branch.priority,
                outcome=branch.outcome,
            )
        )

    def _persist_checkpoint(self, mission_id: str, snapshot: dict[str, Any]) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionCheckpointRecord)
        repo.save(
            MissionCheckpointRecord(
                id=snapshot["checkpoint_id"],
                checkpoint_id=snapshot["checkpoint_id"],
                mission_id=mission_id,
                label=snapshot.get("label", ""),
                snapshot=snapshot,
                created_at_iso=snapshot.get("created_at", ""),
            )
        )

    def _persist_impact(self, mission_id: str, analysis: Any) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionImpactRecord)
        repo.save(
            MissionImpactRecord(
                id=analysis.impact_id,
                impact_id=analysis.impact_id,
                mission_id=mission_id,
                finding_id=analysis.finding_id,
                impact=analysis.to_dict(),
                analyzed_at=analysis.analyzed_at,
            )
        )

    def _persist_telemetry(self, mission: OrchestratedMission) -> None:
        if self._stores is None:
            return
        repo = self._stores.repository_for(MissionTelemetryRecord)
        latest = mission.last_telemetry()
        if latest is None:
            return
        repo.save(
            MissionTelemetryRecord(
                id=_stable_id("telemetry", mission.mission_id, latest.recorded_at),
                snapshot_id=latest.recorded_at,
                mission_id=mission.mission_id,
                snapshot=latest.to_dict(),
                recorded_at=latest.recorded_at,
            )
        )

    def _load_checkpoint(self, mission_id: str, checkpoint_id: str) -> dict[str, Any]:
        if self._stores is None:
            for snapshot in self._engine.get(mission_id).checkpoints:
                if snapshot.get("checkpoint_id") == checkpoint_id:
                    return snapshot
            raise KeyError(checkpoint_id)
        repo = self._stores.repository_for(MissionCheckpointRecord)
        record = repo.get(checkpoint_id)
        if record is None:
            raise KeyError(checkpoint_id)
        return dict(record.snapshot)

    def _publish(self, event_type: str, payload: dict[str, Any]) -> None:
        if self._event_bus is None:
            return
        from hunterx.domain.events import DomainEvent

        self._event_bus.publish(
            DomainEvent(
                event_type=event_type,
                payload=payload,
                source="application.mission_orchestration",
            )
        )


class MissionOrchestrationQueryService:
    """Read persisted mission orchestration records from the TIDB."""

    def __init__(
        self,
        *,
        stores: TidbRepositoryFactory | None = None,
        engine: MissionOrchestrationEngine | None = None,
    ) -> None:
        self._stores = stores
        self._engine = engine

    def _records(self, entity_cls: type, mission_id: str) -> list[Any]:
        if self._stores is None:
            return []
        repo = self._stores.repository_for(entity_cls)
        return [record for record in repo.list(limit=10000) if getattr(record, "mission_id", "") == mission_id]

    def missions(self, *, limit: int = 100, offset: int = 0) -> list[MissionOrchestrationRecord]:
        """Return persisted orchestrated mission records."""
        if self._stores is None:
            return []
        repo = self._stores.repository_for(MissionOrchestrationRecord)
        return list(repo.list(limit=limit, offset=offset))

    def mission(self, mission_id: str) -> MissionOrchestrationRecord | None:
        """Return a persisted mission record by id."""
        records = self._records(MissionOrchestrationRecord, mission_id)
        return records[0] if records else None

    def timeline(self, mission_id: str) -> list[MissionTimelineRecord]:
        """Return timeline records for a mission."""
        return self._records(MissionTimelineRecord, mission_id)

    def decisions(self, mission_id: str) -> list[MissionDecisionRecord]:
        """Return decision records for a mission."""
        return self._records(MissionDecisionRecord, mission_id)

    def hypotheses(self, mission_id: str) -> list[MissionHypothesisRecord]:
        """Return hypothesis records for a mission."""
        return self._records(MissionHypothesisRecord, mission_id)

    def findings(self, mission_id: str) -> list[dict[str, Any]]:
        """Return the findings recorded on the live mission context."""
        if self._engine is None:
            return []
        mission = self._engine.get(mission_id)
        return mission.context.findings

    def attack_paths(self, mission_id: str) -> list[dict[str, Any]]:
        """Return attack paths recorded on the live mission context."""
        if self._engine is None:
            return []
        mission = self._engine.get(mission_id)
        return mission.context.attack_paths

    def coverage(self, mission_id: str) -> list[MissionCoverageRecord]:
        """Return coverage records for a mission."""
        return self._records(MissionCoverageRecord, mission_id)

    def tool_executions(self, mission_id: str) -> list[MissionActionRecord]:
        """Return action/tool-execution records for a mission."""
        return self._records(MissionActionRecord, mission_id)

    def observations(self, mission_id: str) -> list[MissionObservationRecord]:
        """Return observation records for a mission."""
        return self._records(MissionObservationRecord, mission_id)

    def negative_evidence(self, mission_id: str) -> list[MissionNegativeRecord]:
        """Return negative-evidence records for a mission."""
        return self._records(MissionNegativeRecord, mission_id)

    def checkpoints(self, mission_id: str) -> list[MissionCheckpointRecord]:
        """Return checkpoint records for a mission."""
        return self._records(MissionCheckpointRecord, mission_id)

    def impact_analyses(self, mission_id: str) -> list[MissionImpactRecord]:
        """Return impact-analysis records for a mission."""
        return self._records(MissionImpactRecord, mission_id)


_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _stable_id(*parts: Any) -> str:
    """Return a stable 26-char ULID-alphabet id for ``parts``.

    Deterministic hashing gives coverage cells, baselines, objectives and
    telemetry snapshots a stable identity so repeated persists upsert the same
    row instead of accumulating duplicates, while satisfying the TIDB ULID
    envelope contract.
    """
    import hashlib

    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(str(part).encode("utf-8"))
        hasher.update(b"\x1f")
    number = int.from_bytes(hasher.digest()[:16], "big")
    encoded = ""
    for _ in range(26):
        number, remainder = divmod(number, 32)
        encoded = _ULID_ALPHABET[remainder] + encoded
    return encoded


def _with_scope(scope: Any, *, included_targets: tuple[str, ...], excluded_assets: tuple[str, ...], target: str) -> Any:
    """Return a scope dataclass with merged targets."""
    merged = tuple(dict.fromkeys([*(included_targets if target else included_targets), *([target] if target else [])]))
    return dataclasses.replace(
        scope,
        included_targets=merged or scope.included_targets,
        excluded_assets=excluded_assets,
    )


def _strategy_enum(strategy: str) -> StrategyKind:
    """Coerce a strategy name into a :class:`StrategyKind`."""
    try:
        return StrategyKind(strategy)
    except ValueError:
        return StrategyKind.ADAPTIVE


def _mission_from_record(record: MissionOrchestrationRecord) -> OrchestratedMission:
    """Rebuild an :class:`OrchestratedMission` from a persisted record.

    Only the fields the orchestrator needs to resume are reconstructed: the
    adaptive planning aggregate, mission policy, budget, scope target and
    current phase. Detailed reasoning/evidence state is restored on demand by
    the query services.
    """
    from hunterx.domain.adaptive_mission_planning.enums import MissionMode, MissionObjective, MissionState
    from hunterx.domain.adaptive_mission_planning.mission import AdaptiveMission
    from hunterx.domain.mission_orchestration.enums import MissionPhase
    from hunterx.domain.mission_orchestration.models import (
        MissionBudget,
        MissionContext,
        MissionPolicy,
        MissionScope,
    )

    def _enum_or(cls: Any, raw: str, default: Any) -> Any:
        try:
            return cls(raw)
        except (ValueError, TypeError):
            return default

    def _stop_condition(raw: object) -> Any:
        from hunterx.domain.mission_orchestration.enums import StopCondition

        try:
            return StopCondition(str(raw))
        except ValueError:
            return StopCondition.OPERATOR_CANCELLED

    adaptive = AdaptiveMission(
        mission_id=record.mission_id,
        objective=_enum_or(MissionObjective, record.objective, MissionObjective.ATTACK_SURFACE_DISCOVERY),
        mode=_enum_or(MissionMode, record.mode, MissionMode.BALANCED),
        state=_enum_or(MissionState, record.state, MissionState.CREATED),
        authorization_context=record.authorization_context,
        tenant=record.tenant,
    )

    policy_dict = record.policy or {}
    strategy = _enum_or(StrategyKind, record.strategy, StrategyKind.ADAPTIVE)
    policy = MissionPolicy(
        policy_id=str(policy_dict.get("policy_id") or record.mission_id),
        objective_name=str(policy_dict.get("objective_name") or record.objective),
        strategy=strategy,
        allowed_techniques=tuple(policy_dict.get("allowed_techniques") or ()),
        resource_budget=int(policy_dict.get("resource_budget") or 0),
        time_budget_seconds=int(policy_dict.get("time_budget_seconds") or 0),
        validation_depth=str(policy_dict.get("validation_depth") or "standard"),
        proof_depth=str(policy_dict.get("proof_depth") or "standard"),
        coverage_target=float(policy_dict.get("coverage_target") or 0.7),
        stop_conditions=tuple(_stop_condition(item) for item in (policy_dict.get("stop_conditions") or ())),
        max_concurrency=int(policy_dict.get("max_concurrency") or 4),
        rate_limit_per_minute=int(policy_dict.get("rate_limit_per_minute") or 0),
    )

    budget_dict = record.budget or {}
    budget = MissionBudget(
        executions_used=int(budget_dict.get("executions_used") or 0),
        executions_budget=int(budget_dict.get("executions_budget") or policy.resource_budget),
        time_used_seconds=float(budget_dict.get("time_used_seconds") or 0.0),
        time_budget_seconds=int(budget_dict.get("time_budget_seconds") or policy.time_budget_seconds),
        max_concurrency=int(budget_dict.get("max_concurrency") or policy.max_concurrency),
        active_concurrency=int(budget_dict.get("active_concurrency") or 0),
        tool_cost=float(budget_dict.get("tool_cost") or 0.0),
        cpu_percent=float(budget_dict.get("cpu_percent") or 0.0),
        memory_mb=float(budget_dict.get("memory_mb") or 0.0),
        disk_mb=float(budget_dict.get("disk_mb") or 0.0),
        network_kb=float(budget_dict.get("network_kb") or 0.0),
    )

    context = MissionContext(
        mission_id=record.mission_id,
        target_id=record.target,
        scope=MissionScope(
            included_targets=(record.target,) if record.target else (),
            authorization_contexts=(record.authorization_context,),
        ),
        current_phase=record.current_phase,
    )

    mission = OrchestratedMission(
        mission=adaptive,
        context=context,
        policy=policy,
        budget=budget,
        current_phase=_enum_or(MissionPhase, record.current_phase, MissionPhase.TARGET_MODELING),
    )
    mission.context.current_objectives = list(mission.context.current_objectives or ())
    mission.context.remaining_objectives = list(mission.context.remaining_objectives or ())
    return mission
