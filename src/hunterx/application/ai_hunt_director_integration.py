# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Hunt Director Integration for MissionExecutionService.

Provides methods to integrate the AI Hunt Director into the mission execution loop.
"""

from __future__ import annotations

from typing import Any, Optional

from hunterx.application.ai_hunt_director.director import AIHuntDirector
from hunterx.application.ai_hunt_director.protocol import HuntContext
from hunterx.application.ai_hunt_director.executor import DecisionExecutor
from hunterx.application.ai_hunt_director.policy_gate import PolicyGate, PolicyGateConfig


class AIHuntDirectorIntegration:
    """
    Integrates the AI Hunt Director into the MissionExecutionService.

    This class provides methods to:
    - Build HuntContext from mission state
    - Get AI Hunt Director decisions
    - Execute AI decisions through the policy gate and executor
    """

    def __init__(self):
        self._ai_hunt_director = None
        self._orchestration = None
        self._executor = None
        self._policy_gate = None

    def set_ai_hunt_director(
        self,
        ai_hunt_director: Any,
        orchestration_service: Any,
        execution_engine: Any,
        event_bus: Any = None,
    ) -> None:
        """Set the AI Hunt Director and initialize integration components."""
        from hunterx.application.ai_hunt_director.policy_gate import PolicyGate, PolicyGateConfig
        from hunterx.application.ai_hunt_director.executor import DecisionExecutor

        self._ai_hunt_director = ai_hunt_director
        self._orchestration = orchestration_service

        # Initialize policy gate
        self._policy_gate = PolicyGate(PolicyGateConfig())

        # Initialize decision executor
        self._executor = DecisionExecutor(
            orchestration_service=orchestration_service,
            execution_engine=execution_engine,
            policy_gate=self._policy_gate,
            event_bus=event_bus,
        )

    @property
    def is_enabled(self) -> bool:
        """Return True if AI Hunt Director is enabled."""
        return self._ai_hunt_director is not None

    def build_hunt_context(self, mission: Any) -> dict:
        """Build a HuntContext from the mission state."""
        from hunterx.application.ai_hunt_director.protocol import HuntContext, ToolCapability, ResourceState
        from hunterx.domain.mission_orchestration.models import MissionObservation
        from hunterx.domain.mission_orchestration.enums import HypothesisState
        from hunterx.shared.time import utcnow_iso

        # Get available capabilities (placeholder - would be populated from capability registry)
        available_capabilities = []

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
            "available_capabilities": [],
            "available_tools": [],
            "observations": observations,
            "hypotheses": hypotheses,
            "findings": findings,
            "attack_surface": attack_surface,
            "attack_paths": mission.context.attack_paths or [],
            "evidence": evidence,
            "negative_evidence": negative_evidence,
            "resource_state": resource_state.__dict__,
            "ai_provider": "openrouter",
            "ai_model": "deepseek/deepseek-chat",
            "ai_status": "available",
            "previous_decisions": [],
            "previous_actions": [],
            "mission_started_at": "",
            "last_updated_at": "",
            "completion_gate_status": {},
        }

        return context

    def get_ai_decision(self, context: dict) -> Any:
        """Get a decision from the AI Hunt Director."""
        return None

    def execute_ai_decision(self, decision: Any, mission_id: str) -> dict:
        """Execute a validated AI decision through the executor."""
        pass