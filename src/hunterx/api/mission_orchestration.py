# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous Mission Orchestration API routes.

Exposes the mission orchestration application service: create/get/start/pause/
resume/cancel missions and read state, timeline, decisions, hypotheses,
findings, attack paths, coverage and tool executions. Also exposes the
reasoning-loop operations (ingest result, hypotheses, decisions, negative
evidence, baseline/differential testing, branches, confidence, impact,
cascade, checkpoints and stop conditions). Handlers resolve services from the
shared dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)


def build_mission_orchestration_router() -> ApiRouter:
    """Build the ``/missions`` route group."""
    router = ApiRouter(prefix="/missions")

    from hunterx.api.deps import get_container

    def _service() -> MissionOrchestrationService:
        return get_container().resolve(MissionOrchestrationService)

    def _query() -> MissionOrchestrationQueryService:
        return get_container().resolve(MissionOrchestrationQueryService)

    @router.post("", summary="Create an autonomous mission")
    def create_mission(body: dict[str, Any]) -> dict[str, Any]:
        mission = _service().create_mission(
            objective=body.get("objective", "full_security_assessment"),
            mode=body.get("mode", "balanced"),
            target=body.get("target", ""),
            included_targets=tuple(body.get("included_targets", []) or []),
            excluded_assets=tuple(body.get("excluded_assets", []) or []),
            strategy=body.get("strategy", "adaptive"),
            tenant=body.get("tenant", ""),
            authorization_context=body.get("authorization_context", "default"),
            resource_budget=int(body.get("resource_budget", 1000)),
            time_budget_seconds=int(body.get("time_budget_seconds", 0)),
            coverage_target=float(body.get("coverage_target", 0.7)),
            max_concurrency=int(body.get("max_concurrency", 4)),
        )
        return mission.to_dict()

    @router.get("/{mission_id}", summary="Get autonomous mission")
    def get_mission(mission_id: str) -> dict[str, Any]:
        return _service().status(mission_id)

    @router.post("/{mission_id}/start", summary="Start a mission run")
    def start_mission(mission_id: str) -> dict[str, Any]:
        return _service().start(mission_id)

    @router.post("/{mission_id}/pause", summary="Pause a mission")
    def pause_mission(mission_id: str) -> dict[str, Any]:
        return _service().pause(mission_id)

    @router.post("/{mission_id}/resume", summary="Resume a mission")
    def resume_mission(mission_id: str) -> dict[str, Any]:
        return _service().resume(mission_id)

    @router.post("/{mission_id}/cancel", summary="Cancel a mission")
    def cancel_mission(mission_id: str) -> dict[str, Any]:
        return _service().cancel(mission_id)

    @router.post("/{mission_id}/finalize", summary="Finalize a mission")
    def finalize_mission(mission_id: str) -> dict[str, Any]:
        return _service().finalize(mission_id)

    @router.get("/{mission_id}/state", summary="Get mission state")
    def mission_state(mission_id: str) -> dict[str, Any]:
        mission = _service().get(mission_id)
        return {
            "mission_id": mission_id,
            "planning_state": mission.mission.state.value,
            "current_phase": mission.current_phase.value,
            "objective": mission.policy.objective_name,
            "strategy": mission.policy.strategy.value,
            "budget": mission.budget.to_dict(),
            "outcome": mission.outcome.to_dict() if mission.outcome else None,
        }

    @router.get("/{mission_id}/timeline", summary="Get mission timeline")
    def mission_timeline(mission_id: str) -> list[dict[str, Any]]:
        mission = _service().get(mission_id)
        return list(mission.context.history)

    @router.get("/{mission_id}/decisions", summary="Get mission decisions")
    def mission_decisions(mission_id: str) -> list[dict[str, Any]]:
        mission = _service().get(mission_id)
        return [decision.to_dict() for decision in mission.decisions]

    @router.get("/{mission_id}/hypotheses", summary="Get mission hypotheses")
    def mission_hypotheses(mission_id: str) -> list[dict[str, Any]]:
        mission = _service().get(mission_id)
        return [hypothesis.to_dict() for hypothesis in mission.hypotheses]

    @router.get("/{mission_id}/findings", summary="Get mission findings")
    def mission_findings(mission_id: str) -> list[dict[str, Any]]:
        return _query().findings(mission_id)

    @router.get("/{mission_id}/attack-paths", summary="Get mission attack paths")
    def mission_attack_paths(mission_id: str) -> list[dict[str, Any]]:
        return _query().attack_paths(mission_id)

    @router.get("/{mission_id}/coverage", summary="Get mission coverage")
    def mission_coverage(mission_id: str) -> dict[str, Any]:
        return _service().coverage(mission_id)

    @router.get("/{mission_id}/tool-executions", summary="Get mission tool executions")
    def mission_tool_executions(mission_id: str) -> list[dict[str, Any]]:
        mission = _service().get(mission_id)
        return list(mission.context.tool_executions)

    @router.get("/{mission_id}/gaps", summary="Get mission knowledge gaps")
    def mission_gaps(mission_id: str) -> list[dict[str, Any]]:
        return _service().knowledge_gaps(mission_id)

    @router.get("/{mission_id}/explain", summary="Explain the next best action")
    def mission_explain(mission_id: str) -> dict[str, Any]:
        return _service().explain_next(mission_id)

    @router.get("/{mission_id}/telemetry", summary="Get mission telemetry")
    def mission_telemetry(mission_id: str) -> dict[str, Any]:
        return _service().telemetry(mission_id)

    @router.post("/{mission_id}/observations", summary="Ingest a normalized tool result")
    def ingest_observation(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().ingest_result(mission_id, **body)

    @router.post("/{mission_id}/hypotheses", summary="Create a hypothesis")
    def create_hypothesis(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().add_hypothesis(mission_id, **body)

    @router.post("/{mission_id}/hypotheses/{hypothesis_id}/update", summary="Advance a hypothesis")
    def advance_hypothesis(mission_id: str, hypothesis_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().update_hypothesis(mission_id, hypothesis_id, **body)

    @router.post("/{mission_id}/decide", summary="Select the next action by information gain")
    def decide_next(mission_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
        return _service().decide_next(mission_id, **body)

    @router.post("/{mission_id}/negative-evidence", summary="Record bounded negative evidence")
    def record_negative(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().record_negative(mission_id, **body)

    @router.post("/{mission_id}/coverage", summary="Record a coverage cell")
    def record_coverage(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().record_coverage(mission_id, **body)

    @router.post("/{mission_id}/baselines", summary="Capture a baseline observation")
    def capture_baseline(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().capture_baseline(mission_id, **body)

    @router.post("/{mission_id}/differential", summary="Run a differential test")
    def differential_test(mission_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
        return _service().differential_test(mission_id, **body)

    @router.post("/{mission_id}/branches", summary="Open a mission branch")
    def fork_branch(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().fork_branch(mission_id, **body)

    @router.post("/{mission_id}/branches/{branch_id}/resolve", summary="Resolve a mission branch")
    def resolve_branch(mission_id: str, branch_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().resolve_branch(mission_id, branch_id, **body)

    @router.post("/{mission_id}/findings", summary="Register (or update) a finding")
    def register_finding(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().register_finding(mission_id, **body)

    @router.post("/{mission_id}/impact", summary="Analyze impact for a validated finding")
    def analyze_impact(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().analyze_impact(mission_id, **body)

    @router.post("/{mission_id}/cascade", summary="Open follow-on hypotheses (reassessment)")
    def cascade_findings(mission_id: str) -> list[dict[str, Any]]:
        return _service().cascade_findings(mission_id)

    @router.post("/{mission_id}/checkpoints", summary="Create a resumable mission checkpoint")
    def create_checkpoint(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return _service().checkpoint(mission_id, label=body.get("label", ""))

    @router.post("/{mission_id}/checkpoints/{checkpoint_id}/resume", summary="Resume from a checkpoint")
    def resume_checkpoint(mission_id: str, checkpoint_id: str) -> dict[str, Any]:
        return _service().resume_from_checkpoint(mission_id, checkpoint_id)

    @router.get("/{mission_id}/stop-condition", summary="Evaluate mission stop conditions")
    def stop_condition(mission_id: str) -> dict[str, Any]:
        return _service().stop_condition(mission_id)

    return router
