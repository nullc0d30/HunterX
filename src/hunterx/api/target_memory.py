# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence API routes.

Exposes the application services for: target memory, snapshots, snapshot
comparison, changes, observation history, campaigns, campaign intelligence,
coverage, coverage gaps, hypothesis history, risk history, revalidation plans,
finding history and attack-path history. Handlers resolve services from the
shared dependency container.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryService


def build_target_memory_router() -> ApiRouter:
    """Build the ``/targets`` route group for target memory & campaigns."""
    router = ApiRouter(prefix="/targets")

    from hunterx.api.deps import get_container

    def _service() -> TargetMemoryService:
        return get_container().resolve(TargetMemoryService)

    def _query() -> TargetMemoryQueryService:
        return get_container().resolve(TargetMemoryQueryService)

    # -- target memory -------------------------------------------------------

    @router.get("/{target_id}/memory", summary="Get target memory")
    def target_memory(target_id: str) -> dict[str, Any]:
        return _query().memory(target_id).to_dict()

    @router.get("/{target_id}/snapshots", summary="Get target snapshots")
    def snapshots(target_id: str) -> list[dict[str, Any]]:
        return [snapshot.with_state() for snapshot in _query().snapshots(target_id)]

    @router.get("/snapshots/{snapshot_id}", summary="Get a target snapshot")
    def snapshot(snapshot_id: str) -> dict[str, Any]:
        snapshot_record = _query().snapshot(snapshot_id)
        if snapshot_record is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="snapshot not found")
        return snapshot_record.with_state()

    @router.get("/snapshots/{snapshot_a}/compare/{snapshot_b}", summary="Compare two snapshots")
    def compare_snapshots(snapshot_a: str, snapshot_b: str) -> dict[str, Any]:
        diff = _service().diff_snapshots(snapshot_a, snapshot_b)
        return diff.to_dict()

    @router.get("/{target_id}/changes", summary="Get target changes")
    def target_changes(target_id: str) -> list[dict[str, Any]]:
        return _query().changes(target_id)

    @router.get("/{target_id}/history", summary="Get observation history")
    def observation_history(target_id: str) -> list[dict[str, Any]]:
        return [obs.to_dict() for obs in _query().observation_history(target_id)]

    @router.get("/{target_id}/coverage", summary="Get coverage memory")
    def coverage(target_id: str) -> list[dict[str, Any]]:
        return _query().coverage(target_id)

    @router.get("/{target_id}/gaps", summary="Get coverage gaps")
    def coverage_gaps(target_id: str) -> list[dict[str, Any]]:
        return [gap.to_dict() for gap in _query().coverage_gaps(target_id)]

    @router.get("/{target_id}/risk", summary="Get risk history")
    def risk_history(target_id: str) -> list[dict[str, Any]]:
        return [entry.to_dict() for entry in _query().risk_history(target_id)]

    @router.get("/{target_id}/revalidate", summary="Get the revalidation plan")
    def revalidation_plan(target_id: str) -> dict[str, Any]:
        return _query().revalidation_plan(target_id).to_dict()

    @router.get("/{target_id}/hypotheses", summary="Get hypothesis history")
    def hypothesis_history(target_id: str, outcome: str = "") -> list[dict[str, Any]]:
        return [memory.to_dict() for memory in _query().hypothesis_history(target_id, outcome=outcome)]

    @router.get("/{target_id}/findings", summary="Get finding history")
    def finding_history(target_id: str) -> list[dict[str, Any]]:
        return [memory.to_dict() for memory in _query().finding_history(target_id)]

    @router.get("/{target_id}/attack-paths", summary="Get attack-path history")
    def attack_paths(target_id: str) -> list[dict[str, Any]]:
        return [path.to_dict() for path in _query().attack_paths(target_id)]

    # -- campaigns -----------------------------------------------------------

    @router.get("/campaigns", summary="List campaigns")
    def campaigns() -> list[dict[str, Any]]:
        return [campaign.to_dict() for campaign in _query().campaigns()]

    @router.get("/campaigns/{campaign_id}", summary="Get a campaign")
    def campaign(campaign_id: str) -> dict[str, Any]:
        record = _query().campaign(campaign_id)
        if record is None:
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="campaign not found")
        return record.to_dict()

    @router.get("/campaigns/{campaign_id}/intelligence", summary="Get campaign intelligence")
    def campaign_intelligence(campaign_id: str) -> dict[str, Any]:
        return _query().campaign_intelligence(campaign_id).to_dict()

    @router.post("/campaigns", summary="Create a campaign")
    def create_campaign(body: dict[str, Any]) -> dict[str, Any]:
        campaign_record = _service().create_campaign(
            name=body.get("name", ""),
            objective=body.get("objective", ""),
            scope=body.get("scope", ""),
            target_ids=tuple(body.get("target_ids", []) or []),
            tenant=body.get("tenant", ""),
        )
        return campaign_record.to_dict()

    @router.post("/campaigns/{campaign_id}/complete", summary="Complete a campaign")
    def complete_campaign(campaign_id: str) -> dict[str, Any]:
        return _service().complete_campaign(campaign_id).to_dict()

    return router
