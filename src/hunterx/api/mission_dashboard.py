# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission dashboard API routes.

Sprint 033 §33. Operator visibility over an orchestrated mission. This router
adds the dashboard endpoints that the mission orchestration router does not
already expose (``/overview``, ``/attack-surface``, ``/evidence``, ``/proofs``,
``/tools``). Coverage, hypotheses, findings, attack paths and timeline are
already served by the ``/missions`` orchestration route group; registering them
again here would duplicate the surface.
"""

from __future__ import annotations

from typing import Any

from hunterx.api.router import ApiRouter
from hunterx.application.mission_dashboard import MissionDashboardService


def build_mission_dashboard_router() -> ApiRouter:
    """Build the ``/missions`` dashboard route group (new endpoints only)."""
    router = ApiRouter(prefix="/missions")

    from hunterx.api.deps import get_container

    def _service() -> MissionDashboardService:
        return get_container().resolve(MissionDashboardService)

    @router.get("/{mission_id}/overview", summary="Mission overview")
    def overview(mission_id: str) -> dict[str, Any]:
        return _service().overview(mission_id)

    @router.get("/{mission_id}/attack-surface", summary="Unified attack-surface view")
    def attack_surface(mission_id: str) -> dict[str, Any]:
        return _service().attack_surface(mission_id)

    @router.get("/{mission_id}/evidence", summary="Mission evidence view")
    def evidence(mission_id: str) -> dict[str, Any]:
        return _service().evidence(mission_id)

    @router.get("/{mission_id}/proofs", summary="Mission proof view")
    def proofs(mission_id: str) -> dict[str, Any]:
        return _service().proofs(mission_id)

    @router.get("/{mission_id}/tools", summary="Mission tool executions")
    def tools(mission_id: str) -> dict[str, Any]:
        return _service().tools(mission_id)

    return router
