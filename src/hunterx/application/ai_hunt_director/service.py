# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Service.

Application service that integrates the AI Hunt Director with the mission
orchestration layer.
"""

from __future__ import annotations

import contextlib
import dataclasses
from typing import Any, Optional

from hunterx.application.ai_hunt_director.director import AIHuntDirector
from hunterx.application.ai_hunt_director.protocol import (
    AIHuntDecision,
    HuntContext,
)
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.mission_orchestration.enums import MissionPhase, StopCondition
from hunterx.domain.mission_orchestration.models import MissionObservation
from hunterx.domain.mission_orchestration.orchestrator import _OPEN_HYPOTHESIS_STATES
from hunterx.domain.mission_orchestration.models import MissionHypothesis
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class AIHuntDirectorService:
    """Service that integrates the AI Hunt Director with mission orchestration."""

    def __init__(
        self,
        *,
        ai_hunt_director: Optional["AIHuntDirector"] = None,
        orchestration: Optional["MissionOrchestrationService"] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        self._ai_hunt_director = ai_hunt_director
        self._orchestration = orchestration
        self._event_bus = event_bus
        self._current_context: dict[str, Any] = {}

    @property
    def is_enabled(self) -> bool:
        """Return True if AI Hunt Director is enabled."""
        return self._ai_hunt_director is not None

    def enable(self, ai_hunt_director: "AIHuntDirector") -> None:
        """Enable the AI Hunt Director."""
        self._ai_hunt_director = ai_hunt_director

    def disable(self) -> None:
        """Disable the AI Hunt Director."""
        self._ai_hunt_director = None

    def run_hunt(
        self,
        mission_id: str,
        *,
        max_cycles: int = 100,
        max_idle_cycles: int = 3,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run a mission with AI-directed autonomous hunting.

        This is the main entry point for AI-directed missions. It replaces
        the deterministic run loop with AI-directed decision making.
        """
        from hunterx.application.mission_execution import MissionExecutionService

        # Create a temporary execution service with AI Hunt Director
        # This is a simplified version - in reality, we'd inject the AI Hunt Director
        # into the MissionExecutionService
        from hunterx.application.mission_execution import MissionExecutionService

        # Delegate to the existing execution service with AI Hunt Director
        # For now, delegate to the existing run method but with AI Hunt Director enabled
        from hunterx.application.mission_execution import MissionExecutionService

        # We need to create a modified execution service
        # For now, delegate to the existing implementation
        from hunterx.application.mission_execution import MissionExecutionService as ExecutionService

        # Use the existing run method but with AI Hunt Director enabled
        # This is a placeholder - the full integration requires more changes
        return self._orchestration.run(mission_id) if hasattr(self._orchestration, 'run') else {
            "status": "not_implemented",
            "message": "AI Hunt Director integration pending"
        }

    def build_hunt_context(self, mission_id: str) -> Optional[dict]:
        """Build the hunt context for the AI Hunt Director."""
        if not self._orchestration:
            return None

        mission = self._orchestration.get(mission_id)

        # Build the hunt context
        from hunterx.application.ai_hunt_director.protocol import HuntContext, ToolCapability, ResourceState
        from hunterx.domain.mission_orchestration.models import MissionObservation
        from hunterx.domain.mission_orchestration.enums import HypothesisState

        # Get available capabilities
        available_capabilities = self._get_available_capabilities(mission_id)

        # Build observations
        observations = []
        for obs in mission.observations:
            observations.append({
                "observation_id": obs.observation_id,
                "observation_type": obs.observation_type,
                "tool_id": obs.tool_id,
                "asset_key": obs.asset_key,
                "content_summary": str(obs.content)[:500],
                "evidence_ref": obs.evidence_ref,
                "confidence": obs.confidence,
                "provenance": obs.provenance,
            })

        # Build hypotheses
        hypotheses = []
        for hyp in mission.hypotheses:
            hypotheses.append({
                "hypothesis_id": hyp.hypothesis_id,
                "statement": hyp.statement,
                "state": hyp.state.value,
                "category": str(hyp.category),
                "vulnerability_class": str(hyp.provenance.get("vulnerability_class", "")),
                "priority": hyp.priority,
                "confidence": hyp.confidence,
                "supporting_evidence": list(hyp.supporting_evidence),
                "contradicting_evidence": list(hyp.contradicting_evidence),
                "tested_actions": list(hyp.tested_actions),
                "created_at": hyp.created_at,
                "updated_at": hyp.updated_at,
                "provenance": hyp.provenance,
            })

        # Build findings
        findings = []
        for finding in mission.context.findings:
            findings.append({
                "finding_id": finding.get("finding_id", ""),
                "vulnerability_class": finding.get("vulnerability_class", ""),
                "title": finding.get("title", ""),
                "target": finding.get("target", ""),
                "severity": finding.get("severity", ""),
                "stage": finding.get("stage", ""),
                "confidence": finding.get("confidence", 0.0),
                "evidence_refs": finding.get("evidence_refs", []),
                "hypothesis_id": finding.get("hypothesis_id", ""),
            })

        # Build attack surface
        attack_surface = {
            "services": mission.context.services,
            "endpoints": mission.context.endpoints,
            "parameters": mission.context.parameters,
            "assets": mission.context.assets,
        }

        # Build attack paths
        attack_paths = mission.context.attack_paths or []

        # Build evidence
        evidence = mission.context.evidence or {}

        # Build negative evidence
        negative_evidence = [record.to_dict() for record in mission.negative_evidence] if mission.negative_evidence else []

        # Build resource state
        from hunterx.application.ai_hunt_director.protocol import ResourceState
        resource_state = ResourceState(
            execution_remaining=mission.budget.executions_budget - mission.budget.executions_used,
            time_remaining=mission.budget.time_budget_seconds - mission.budget.time_used_seconds if mission.budget.time_budget_seconds else 0,
            available_capabilities=list(mission.context.tool_executions),
            provider_status={},
            concurrent_executions=0,
            max_concurrency=4,
        )

        # Build context
        context = {
            "mission_id": mission.mission_id,
            "target": mission.context.target_id,
            "objective": "full_security_assessment",
            "scope": {"included": [mission.context.target_id]},
            "authorization_context": {"context": "default"},
            "current_phase": "reconnaissance",
            "current_strategy": "adaptive",
            "available_capabilities": [],  # TODO: populate from capability registry
            "available_tools": [],
            "observations": observations,
            "hypotheses": [],
            "findings": findings,
            "attack_surface": attack_surface,
            "attack_paths": attack_paths,
            "evidence": {},
            "negative_evidence": negative_evidence,
            "resource_state": resource_state.__dict__,
            "ai_provider": "openrouter",
            "ai_model": "deepseek/deepseek-chat",
            "ai_status": "available",
            "previous_decisions": [],
            "previous_actions": [],
            "mission_started_at": mission.created_at if hasattr(mission, 'created_at') else "",
            "last_updated_at": utcnow_iso(),
            "completion_gate_status": {},
        }

        return context

    def _get_available_capabilities(self, mission_id: str) -> list:
        """Get available capabilities for the mission."""
        # This would query the capability registry
        return []

    def _execute_ai_decision(self, mission_id: str, decision: Any) -> dict:
        """Execute an AI Hunt Director decision."""
        # This would integrate with the policy gate and execution engine
        return {"status": "not_implemented"}


# Placeholder for the actual implementation
# The full implementation requires integrating with the mission execution service
# and the AI Hunt Director protocol