# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration — engine facade.

Sprint 032. The :class:`MissionOrchestrationEngine` is the runtime facade of the
autonomous mission orchestration layer. It delegates the adaptive loop to the
pure domain :class:`MissionOrchestrator` (hypothesis loop, decision engine,
baseline/differential testing, negative evidence, coverage, knowledge gaps,
confidence, branches, telemetry, reasoning trace, policies, impact, cascade)
and the underlying Sprint 027 :class:`AdaptiveMissionPlanningEngine` for plan
mutation, attack paths, tool selection and failure recovery.

The facade keeps the domain layer pure: it is injected with the pure engines
and only wires them together.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.mission_orchestration.baseline import BaselineObservation
from hunterx.domain.mission_orchestration.confidence import ConfidenceResult
from hunterx.domain.mission_orchestration.decision import MissionDecision
from hunterx.domain.mission_orchestration.enums import MissionPhase, StopCondition
from hunterx.domain.mission_orchestration.gap import KnowledgeGap
from hunterx.domain.mission_orchestration.mission import OrchestratedMission
from hunterx.domain.mission_orchestration.models import (
    ImpactAnalysis,
    MissionBranch,
    MissionHypothesis,
    MissionObservation,
    NegativeEvidenceRecord,
    NovelBehaviorRecord,
)
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.mission_orchestration.policy import PolicyVerdict


class MissionOrchestrationEngine:
    """Runtime facade of the autonomous mission orchestration layer.

    Attributes:
        orchestrator: the pure domain orchestrator composing the engines.

    """

    def __init__(self, orchestrator: MissionOrchestrator | None = None) -> None:
        self.orchestrator = orchestrator or MissionOrchestrator()

    # -- lifecycle ----------------------------------------------------------

    def create_mission(self, **kwargs: Any) -> OrchestratedMission:
        """Create an orchestrated mission."""
        return self.orchestrator.create_mission(**kwargs)

    def get(self, mission_id: str) -> OrchestratedMission:
        """Return an orchestrated mission."""
        return self.orchestrator.get(mission_id)

    def restore(self, mission: OrchestratedMission) -> OrchestratedMission:
        """Register an already-persisted mission back into the in-memory store."""
        return self.orchestrator.restore(mission)

    def missions(self) -> list[OrchestratedMission]:
        """Return all registered orchestrated missions."""
        return self.orchestrator.missions()

    def start(self, mission_id: str) -> OrchestratedMission:
        """Start a mission run."""
        return self.orchestrator.start(mission_id)

    def pause(self, mission_id: str) -> OrchestratedMission:
        """Pause a mission."""
        return self.orchestrator.pause(mission_id)

    def resume(self, mission_id: str) -> OrchestratedMission:
        """Resume a mission."""
        return self.orchestrator.resume(mission_id)

    def cancel(self, mission_id: str) -> OrchestratedMission:
        """Cancel a mission."""
        return self.orchestrator.cancel(mission_id)

    def finalize(self, mission_id: str, **kwargs: Any) -> OrchestratedMission:
        """Finalize a mission."""
        return self.orchestrator.finalize(mission_id, **kwargs)

    def sync_phase(self, mission_id: str) -> MissionPhase:
        """Synchronize the orchestration phase from the planning state."""
        return self.orchestrator.sync_phase(mission_id)

    # -- reasoning loop -----------------------------------------------------

    def ingest_result(self, mission_id: str, **kwargs: Any) -> MissionObservation:
        """Ingest and normalize a tool result."""
        return self.orchestrator.ingest_result(mission_id, **kwargs)

    def add_hypothesis(self, mission_id: str, **kwargs: Any) -> MissionHypothesis:
        """Create a hypothesis."""
        return self.orchestrator.add_hypothesis(mission_id, **kwargs)

    def update_hypothesis(self, mission_id: str, hypothesis_id: str, **kwargs: Any) -> MissionHypothesis:
        """Advance a hypothesis."""
        return self.orchestrator.update_hypothesis(mission_id, hypothesis_id, **kwargs)

    def verify_hypothesis(self, mission_id: str, hypothesis_id: str, **kwargs: Any) -> MissionHypothesis:
        """Verify a supported hypothesis."""
        return self.orchestrator.verify_hypothesis(mission_id, hypothesis_id, **kwargs)

    def decide_next(self, mission_id: str, **kwargs: Any) -> MissionDecision | None:
        """Select the next action by information gain."""
        return self.orchestrator.decide_next(mission_id, **kwargs)

    def decide(self, mission_id: str, **kwargs: Any) -> MissionDecision | None:
        """Alias for :meth:`decide_next`."""
        return self.decide_next(mission_id, **kwargs)

    def explain_next(self, mission_id: str) -> dict[str, Any]:
        """Explain the next best action."""
        return self.orchestrator.explain_next(mission_id)

    def explain_decision(self, mission_id: str, decision_id: str = "") -> dict[str, Any] | None:
        """Return an explainable decision record."""
        return self.orchestrator.explain_decision(mission_id, decision_id)

    def record_negative(self, mission_id: str, **kwargs: Any) -> NegativeEvidenceRecord:
        """Record bounded negative evidence."""
        return self.orchestrator.record_negative(mission_id, **kwargs)

    def record_coverage(self, mission_id: str, **kwargs: Any) -> None:
        """Record a coverage cell."""
        self.orchestrator.record_coverage(mission_id, **kwargs)

    def knowledge_gaps(self, mission_id: str) -> list[KnowledgeGap]:
        """Return ranked knowledge gaps."""
        return self.orchestrator.knowledge_gaps(mission_id)

    def coverage_summary(self, mission_id: str) -> dict[str, Any]:
        """Return the coverage summary."""
        return self.orchestrator.coverage_summary(mission_id)

    def capture_baseline(self, mission_id: str, **kwargs: Any) -> BaselineObservation:
        """Capture a baseline observation."""
        return self.orchestrator.capture_baseline(mission_id, **kwargs)

    def differential_test(self, mission_id: str, **kwargs: Any) -> Any:
        """Run a differential test."""
        return self.orchestrator.differential_test(mission_id, **kwargs)

    def fork_branch(self, mission_id: str, **kwargs: Any) -> MissionBranch:
        """Open a mission branch."""
        return self.orchestrator.fork_branch(mission_id, **kwargs)

    def resolve_branch(self, mission_id: str, branch_id: str, **kwargs: Any) -> MissionBranch:
        """Resolve a mission branch."""
        return self.orchestrator.resolve_branch(mission_id, branch_id, **kwargs)

    def compute_confidence(self, mission_id: str, **kwargs: Any) -> ConfidenceResult:
        """Compute an evidence-driven confidence score."""
        return self.orchestrator.compute_confidence(mission_id, **kwargs)

    def analyze_impact(self, mission_id: str, **kwargs: Any) -> ImpactAnalysis:
        """Analyze impact for a validated finding."""
        return self.orchestrator.analyze_impact(mission_id, **kwargs)

    def cascade_findings(self, mission_id: str) -> list[MissionHypothesis]:
        """Open follow-on hypotheses from validated findings."""
        return self.orchestrator.cascade_findings(mission_id)

    def register_finding(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Register (or update) a finding."""
        return self.orchestrator.register_finding(mission_id, **kwargs)

    def start_novel(self, mission_id: str, **kwargs: Any) -> NovelBehaviorRecord:
        """Open a novel-behavior record."""
        return self.orchestrator.start_novel(mission_id, **kwargs)

    def advance_novel(self, mission_id: str, record_id: str, **kwargs: Any) -> NovelBehaviorRecord:
        """Advance a novel-behavior record."""
        return self.orchestrator.advance_novel(mission_id, record_id, **kwargs)

    def checkpoint(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        """Snapshot resumable mission state."""
        return self.orchestrator.checkpoint(mission_id, **kwargs)

    def resume_from_checkpoint(self, mission_id: str, checkpoint: dict[str, Any]) -> OrchestratedMission:
        """Restore a mission from a checkpoint."""
        return self.orchestrator.resume_from_checkpoint(mission_id, checkpoint)

    def check_action(self, mission_id: str, **kwargs: Any) -> PolicyVerdict:
        """Evaluate the policy gates for an action."""
        return self.orchestrator.check_action(mission_id, **kwargs)

    def stop_condition(self, mission_id: str) -> StopCondition | None:
        """Evaluate the mission stop conditions."""
        return self.orchestrator.stop_condition(mission_id)

    def record_ai_trace(self, mission_id: str, *, decision_id: str = "", **trace: Any) -> None:
        """Record an AI-invocation provenance trace entry (best-effort)."""
        return self.orchestrator.record_ai_trace(mission_id, decision_id=decision_id, **trace)

    def telemetry(self, mission_id: str) -> dict[str, Any]:
        """Return the latest telemetry snapshot."""
        mission = self.orchestrator.get(mission_id)
        latest = mission.last_telemetry()
        return latest.to_dict() if latest else {}


__all__ = ["MissionOrchestrationEngine"]
