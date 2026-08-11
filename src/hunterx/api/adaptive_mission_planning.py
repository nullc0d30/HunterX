# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive Mission & Attack-Path Planning API routes.

Exposes the application services for: create mission, get current plan, get
plan history, get candidate actions, approve action, pause/resume, replan,
attack paths, decision explanation, coverage, evidence gaps and proof gaps.
Handlers resolve services from the shared dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.adaptive_mission_planning import AdaptiveMissionPlanningService
from hunterx.domain.adaptive_mission_planning.enums import ReplanTrigger


def build_adaptive_mission_planning_router() -> ApiRouter:
    """Build the ``/missions/adaptive`` route group."""
    router = ApiRouter(prefix="/missions/adaptive")

    from hunterx.api.deps import get_container

    def _service() -> AdaptiveMissionPlanningService:
        return get_container().resolve(AdaptiveMissionPlanningService)

    @router.post("", summary="Create an adaptive mission")
    def create_mission(body: dict[str, Any]) -> dict[str, Any]:
        service = _service()
        mission = service.create_mission(
            objective=body.get("objective", "attack_surface_discovery"),
            mode=body.get("mode", "balanced"),
            scope=body.get("scope", ""),
            included_targets=tuple(body.get("included_targets", []) or []),
            excluded_assets=tuple(body.get("excluded_assets", []) or []),
            excluded_capabilities=tuple(body.get("excluded_capabilities", []) or []),
            time_budget_seconds=int(body.get("time_budget_seconds", 0)),
            max_concurrency=int(body.get("max_concurrency", 4)),
            risk_threshold=float(body.get("risk_threshold", 0.8)),
            authorization_context=body.get("authorization_context", "default"),
            safety_ceiling=body.get("safety_ceiling", "low_impact_active"),
            tenant=body.get("tenant", ""),
            target=body.get("target", ""),
        )
        return mission.to_dict()

    @router.get("/{mission_id}", summary="Get adaptive mission status")
    def mission_status(mission_id: str) -> dict[str, Any]:
        return _service().status(mission_id).to_dict()

    @router.get("/{mission_id}/plan", summary="Get the current execution plan")
    def current_plan(mission_id: str) -> dict[str, Any]:
        return _service().current_plan(mission_id)

    @router.get("/{mission_id}/plan/history", summary="Get the plan version history")
    def plan_history(mission_id: str) -> list[dict[str, Any]]:
        return [version.to_dict() for version in _service().plan_history(mission_id)]

    @router.get("/{mission_id}/plan/{version}", summary="Get a specific plan version")
    def plan_version(mission_id: str, version: int) -> dict[str, Any]:
        return _service().plan_version(mission_id, version).to_dict()

    @router.get("/{mission_id}/candidates", summary="Get ranked candidate actions")
    def candidate_actions(mission_id: str) -> dict[str, Any]:
        return _service().candidate_actions(mission_id).to_dict()

    @router.post("/{mission_id}/approve/{action_id}", summary="Approve an action")
    def approve_action(mission_id: str, action_id: str) -> dict[str, Any]:
        return _service().approve_action(mission_id, action_id).to_dict()

    @router.post("/{mission_id}/replan", summary="Replan a mission")
    def replan_mission(mission_id: str, body: dict[str, Any]) -> dict[str, Any]:
        trigger = body.get("trigger", "new_asset_discovered")
        trigger_enum = ReplanTrigger(trigger)
        delta = _service().replan(
            mission_id,
            trigger=trigger_enum,
            asset_key=body.get("asset_key", ""),
            detail=body.get("detail"),
            reason=body.get("reason", ""),
        )
        return delta.to_dict()

    @router.post("/{mission_id}/pause", summary="Pause a mission")
    def pause_mission(mission_id: str) -> dict[str, Any]:
        return _service().pause(mission_id).to_dict()

    @router.post("/{mission_id}/resume", summary="Resume a mission")
    def resume_mission(mission_id: str) -> dict[str, Any]:
        return _service().resume(mission_id).to_dict()

    @router.get("/{mission_id}/paths", summary="Get attack paths")
    def attack_paths(mission_id: str) -> list[dict[str, Any]]:
        return [path.to_dict() for path in _service().attack_paths(mission_id)]

    @router.get("/{mission_id}/explain", summary="Explain the next best action")
    def explain(mission_id: str) -> dict[str, Any]:
        return _service().explain_next(mission_id)

    @router.get("/{mission_id}/coverage", summary="Get mission coverage")
    def coverage(mission_id: str) -> dict[str, Any]:
        return _service().coverage(mission_id)

    @router.get("/{mission_id}/gaps/evidence", summary="Get evidence gaps")
    def evidence_gaps(mission_id: str) -> list[dict[str, Any]]:
        return [gap.to_dict() for gap in _service().evidence_gaps(mission_id)]

    @router.get("/{mission_id}/gaps/proof", summary="Get proof gaps")
    def proof_gaps(mission_id: str) -> list[dict[str, Any]]:
        return [gap.to_dict() for gap in _service().proof_gaps(mission_id)]

    @router.post("/{mission_id}/checkpoints", summary="Create a mission checkpoint")
    def checkpoint(mission_id: str) -> dict[str, Any]:
        return _service().checkpoint_create(mission_id).to_dict()

    @router.post("/{mission_id}/checkpoints/{checkpoint_id}/resume", summary="Resume from a checkpoint")
    def resume_checkpoint(mission_id: str, checkpoint_id: str) -> dict[str, Any]:
        return _service().resume_from_checkpoint(mission_id, checkpoint_id).to_dict()

    return router
