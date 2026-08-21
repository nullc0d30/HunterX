# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission dashboard & operator visibility.

Sprint 033. Aggregates live mission state into operator-facing dashboard views:
overview, attack surface, coverage, hypotheses, findings, evidence, proofs,
attack paths, tools and timeline. The service composes the orchestration engine
and the TIDB query service — it does not duplicate the mission domain. Views
are read-only projections over the orchestrated mission aggregate and its
persisted records.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)
from hunterx.domain.mission_orchestration.mission import OrchestratedMission

_VALIDATED_STAGES = ("verified", "proven", "report_ready")
_PROOF_STATES = ("proved", "validated")


class MissionDashboardService:
    """Compose operator-facing dashboard views for an orchestrated mission.

    Attributes:
        service: the mission orchestration service (live aggregate access).
        query: the mission orchestration query service (TIDB record access).

    """

    def __init__(
        self,
        *,
        service: MissionOrchestrationService | None = None,
        query: MissionOrchestrationQueryService | None = None,
    ) -> None:
        self._service = service
        self._query = query

    def _mission(self, mission_id: str) -> OrchestratedMission:
        if self._service is None:
            raise LookupError("mission orchestration service is not wired")
        return self._service.get(mission_id)

    # -- overview -----------------------------------------------------------

    def overview(self, mission_id: str) -> dict[str, Any]:
        """Return the mission overview: state, counts, coverage, budget."""
        mission = self._mission(mission_id)
        context = mission.context
        findings = context.findings
        validated = sum(1 for finding in findings if finding.get("stage") in _VALIDATED_STAGES)
        report_ready = sum(1 for finding in findings if finding.get("stage") == "report_ready")
        open_hypotheses = len(mission.open_hypotheses())
        telemetry = mission.last_telemetry()
        return {
            "mission_id": mission_id,
            "target_id": context.target_id,
            "objective": mission.policy.objective_name,
            "strategy": mission.policy.strategy.value,
            "planning_state": mission.mission.state.value,
            "current_phase": mission.current_phase.value,
            "scope": context.scope.to_dict(),
            "counts": {
                "assets": len(context.assets),
                "technologies": len(context.technologies),
                "services": len(context.services),
                "endpoints": len(context.endpoints),
                "parameters": len(context.parameters),
                "observations": len(mission.observations),
                "hypotheses": len(mission.hypotheses),
                "open_hypotheses": open_hypotheses,
                "findings": len(findings),
                "validated_findings": validated,
                "report_ready_findings": report_ready,
                "evidence": len(context.evidence),
                "proofs": len(context.proofs),
                "attack_paths": len(context.attack_paths),
                "tool_executions": len(context.tool_executions),
                "decisions": len(mission.decisions),
                "negative_evidence": len(mission.negative_evidence),
            },
            "coverage_ratio": mission.coverage_ratio(),
            "coverage_dimensions": mission.coverage_dimensions(),
            "budget": mission.budget.to_dict(),
            "telemetry": telemetry.to_dict() if telemetry else None,
            "outcome": mission.outcome.to_dict() if mission.outcome else None,
            "updated_at": context.updated_at,
        }

    # -- attack surface -----------------------------------------------------

    def attack_surface(self, mission_id: str) -> dict[str, Any]:
        """Return the unified attack-surface view of the mission context."""
        context = self._mission(mission_id).context
        return {
            "mission_id": mission_id,
            "target_id": context.target_id,
            "assets": list(context.assets.values()),
            "technologies": list(context.technologies.values()),
            "services": list(context.services.values()),
            "endpoints": list(context.endpoints.values()),
            "parameters": list(context.parameters.values()),
            "contexts": list(context.contexts.values()),
        }

    # -- coverage -----------------------------------------------------------

    def coverage(self, mission_id: str) -> dict[str, Any]:
        """Return the coverage summary for the mission."""
        if self._service is None:
            raise LookupError("mission orchestration service is not wired")
        return self._service.coverage(mission_id)

    # -- hypotheses ---------------------------------------------------------

    def hypotheses(self, mission_id: str) -> list[dict[str, Any]]:
        """Return hypothesis records for the mission."""
        return [hypothesis.to_dict() for hypothesis in self._mission(mission_id).hypotheses]

    # -- findings -----------------------------------------------------------

    def findings(self, mission_id: str) -> list[dict[str, Any]]:
        """Return findings recorded on the mission context."""
        return list(self._mission(mission_id).context.findings)

    # -- evidence -----------------------------------------------------------

    def evidence(self, mission_id: str) -> dict[str, Any]:
        """Return the aggregated evidence view of the mission.

        Includes observations (normalized tool output), negative evidence,
        baselines, differential results, impact analyses and any evidence
        records carried on the mission context.
        """
        mission = self._mission(mission_id)
        return {
            "mission_id": mission_id,
            "observations": [observation.to_dict() for observation in mission.observations],
            "negative_evidence": [record.to_dict() for record in mission.negative_evidence],
            "baselines": [baseline.to_dict() for baseline in mission.baselines],
            "differential_results": [result.to_dict() for result in mission.differential_results],
            "impact_analyses": [analysis.to_dict() for analysis in mission.impact_analyses],
            "evidence_records": list(mission.context.evidence.values()),
        }

    # -- proofs -------------------------------------------------------------

    def proofs(self, mission_id: str) -> dict[str, Any]:
        """Return the proof view: proved coverage, proofs and PoC records."""
        mission = self._mission(mission_id)
        proved_cells = [
            cell.to_dict()
            for cell in mission.coverage_cells()
            if cell.state.value in _PROOF_STATES
        ]
        findings_with_proof = [
            finding
            for finding in mission.context.findings
            if finding.get("stage") in _VALIDATED_STAGES
        ]
        return {
            "mission_id": mission_id,
            "proved_cells": proved_cells,
            "findings_with_proof": findings_with_proof,
            "proofs": list(mission.context.proofs.values()),
            "impact_analyses": [analysis.to_dict() for analysis in mission.impact_analyses],
        }

    # -- attack paths -------------------------------------------------------

    def attack_paths(self, mission_id: str) -> dict[str, Any]:
        """Return the attack-path view.

        Combines the mission-context attack paths with the adaptive planning
        attack paths (the richer, evidence-aware source) when available.
        """
        mission = self._mission(mission_id)
        planning_paths = [
            path.to_dict() for path in getattr(mission.mission, "attack_paths", ())
        ]
        return {
            "mission_id": mission_id,
            "planning_paths": planning_paths,
            "context_paths": list(mission.context.attack_paths),
            "path_count": len(planning_paths) + len(mission.context.attack_paths),
        }

    # -- tools --------------------------------------------------------------

    def tools(self, mission_id: str) -> dict[str, Any]:
        """Return tool executions plus tool utilization telemetry."""
        mission = self._mission(mission_id)
        telemetry = mission.last_telemetry()
        return {
            "mission_id": mission_id,
            "tool_executions": list(mission.context.tool_executions),
            "utilization": telemetry.tool_utilization if telemetry else 0.0,
            "failed_actions": telemetry.failed_actions if telemetry else 0,
            "fallback_rate": telemetry.fallback_rate if telemetry else 0.0,
            "execution_count": len(mission.context.tool_executions),
        }

    # -- timeline -----------------------------------------------------------

    def timeline(self, mission_id: str) -> list[dict[str, Any]]:
        """Return the mission history timeline."""
        return list(self._mission(mission_id).context.history)

    # -- persisted records (TIDB) -------------------------------------------

    def records(self, mission_id: str) -> dict[str, Any]:
        """Return persisted TIDB records for a mission when available."""
        if self._query is None:
            return {}
        return {
            "mission": _record_dict(self._query.mission(mission_id)),
            "timeline": [_record_dict(record) for record in self._query.timeline(mission_id)],
            "decisions": [_record_dict(record) for record in self._query.decisions(mission_id)],
            "hypotheses": [_record_dict(record) for record in self._query.hypotheses(mission_id)],
            "coverage": [_record_dict(record) for record in self._query.coverage(mission_id)],
            "tool_executions": [
                _record_dict(record) for record in self._query.tool_executions(mission_id)
            ],
            "observations": [
                _record_dict(record) for record in self._query.observations(mission_id)
            ],
            "negative_evidence": [
                _record_dict(record) for record in self._query.negative_evidence(mission_id)
            ],
            "checkpoints": [
                _record_dict(record) for record in self._query.checkpoints(mission_id)
            ],
            "impact_analyses": [
                _record_dict(record) for record in self._query.impact_analyses(mission_id)
            ],
        }


def _record_dict(record: Any) -> dict[str, Any]:
    """Serialize a TIDB record dataclass to a JSON-safe mapping."""
    if record is None:
        return {}
    from dataclasses import asdict

    payload: dict[str, Any] = asdict(record)
    return {key: value for key, value in payload.items() if not key.startswith("_")}


__all__ = ["MissionDashboardService"]
