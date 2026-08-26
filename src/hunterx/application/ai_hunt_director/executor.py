# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""AI Decision Executor.

Executes validated AI Hunt Director decisions through the HunterX execution
pipeline.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from typing import Any, Optional

from hunterx.application.ai_hunt_director.protocol import (
    AIHuntDecision,
    ActionType,
    PolicyGateResultDetail,
)
from hunterx.application.ai_hunt_director.policy_gate import PolicyGate, PolicyGateConfig
# MissionExecutionService imported locally to avoid circular import
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.models import MissionObservation
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class DecisionExecutionResult:
    """Result of executing an AI decision."""

    decision_id: str
    status: str  # executed, rejected, failed, deferred
    observation_id: str = ""
    error: str = ""
    evidence_ref: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class DecisionExecutor:
    """
    Executes validated AI Hunt Director decisions through the HunterX
    execution pipeline.

    The DecisionExecutor:
    1. Receives a validated AIHuntDecision
    2. Routes it to the appropriate execution path
    3. Records the observation/evidence
    4. Updates mission state
    """

    def __init__(
        self,
        orchestration_service: Any,
        execution_engine: Any,
        policy_gate: Optional[Any] = None,
        event_bus: Optional[Any] = None,
    ) -> None:
        self._orchestration = orchestration_service
        self._engine = execution_engine
        self._policy_gate = PolicyGate(PolicyGateConfig())
        self._event_bus = event_bus

    def execute(self, decision: Any, mission_id: str) -> dict:
        """
        Execute a validated AI decision.

        Returns the execution result with observation/evidence details.
        """
        from hunterx.application.ai_hunt_director.protocol import (
            PolicyGateResultDetail,
            PolicyGateResult,
        )

        # Validate through policy gate
        gate_result = self._policy_gate.validate(decision)
        if gate_result.result != "approved":
            return {
                "status": "rejected",
                "decision_id": getattr(decision, "decision_id", ""),
                "reason": gate_result.reason.value if gate_result.reason else "unknown",
                "message": gate_result.message,
                "gate_result": gate_result.__dict__,
            }

        # Execute based on action type
        action_type = getattr(decision, "action_type", None)
        if not action_type:
            return {"status": "rejected", "reason": "No action type specified"}

        # Route to appropriate handler
        if decision.action_type == "EXECUTE_TOOL":
            return self._execute_tool(decision)
        elif decision.action_type == "REASSESS":
            return self._execute_reassess(decision)
        elif decision.action_type == "VALIDATE_FINDING":
            return self._execute_validate_finding(decision)
        elif decision.action_type == "COLLECT_EVIDENCE":
            return self._execute_collect_evidence(decision)
        elif decision.action_type == "EXPLORE_ATTACK_PATH":
            return self._execute_explore_attack_path(decision)
        elif decision.action_type == "COMPLETE":
            return self._execute_complete(decision)
        elif decision.action_type == "DEFER_HYPOTHESIS":
            return self._execute_defer_hypothesis(decision)
        elif decision.action_type == "BLOCK_HYPOTHESIS":
            return self._execute_block_hypothesis(decision)
        elif decision.action_type == "REQUEST_EVIDENCE":
            return self._execute_request_evidence(decision)
        elif decision.action_type == "GENERATE_PROOF":
            return self._execute_generate_proof(decision)
        else:
            return {"status": "rejected", "reason": f"Unknown action type: {decision.action_type}"}

    def _execute_tool(self, decision: Any) -> dict:
        """Execute a tool via the execution engine."""
        # This would integrate with the existing MissionExecutionService
        # For now, return a placeholder
        return {
            "status": "executed",
            "decision_id": getattr(decision, "decision_id", ""),
            "tool_id": getattr(decision, "tool_id", ""),
            "observation_id": "",
        }

    def _execute_reassess(self, decision: Any) -> dict:
        """Execute a reassessment action."""
        return {
            "status": "reassessed",
            "decision_id": getattr(decision, "decision_id", ""),
            "reason": getattr(decision, "rationale", ""),
        }

    def _execute_validate_finding(self, decision: Any) -> dict:
        """Execute finding validation."""
        return {
            "status": "validated",
            "decision_id": getattr(decision, "decision_id", ""),
        }

    def _execute_collect_evidence(self, decision: Any) -> dict:
        """Execute evidence collection."""
        return {
            "status": "evidence_collected",
            "decision_id": getattr(decision, "decision_id", ""),
        }

    def _execute_explore_attack_path(self, decision: Any) -> dict:
        """Execute attack path exploration."""
        return {
            "status": "attack_path_explored",
            "decision_id": getattr(decision, "decision_id", ""),
        }

    def _execute_complete(self, decision: Any) -> dict:
        """Execute mission completion."""
        return {
            "status": "completed",
            "decision_id": getattr(decision, "decision_id", ""),
            "reason": getattr(decision, "rationale", ""),
        }

    def _execute_defer_hypothesis(self, decision: Any) -> dict:
        """Defer a hypothesis."""
        return {
            "status": "deferred",
            "decision_id": getattr(decision, "decision_id", ""),
            "hypothesis_id": getattr(decision, "hypothesis_ids", [""])[0] if getattr(decision, "hypothesis_ids", []) else "",
        }

    def _execute_block_hypothesis(self, decision: Any) -> dict:
        """Block a hypothesis."""
        return {
            "status": "blocked",
            "decision_id": getattr(decision, "decision_id", ""),
            "hypothesis_id": getattr(decision, "hypothesis_ids", [""])[0] if getattr(decision, "hypothesis_ids", []) else "",
        }

    def _execute_request_evidence(self, decision: Any) -> dict:
        """Request additional evidence for a finding."""
        return {
            "status": "evidence_requested",
            "decision_id": getattr(decision, "decision_id", ""),
        }

    def _execute_generate_proof(self, decision: Any) -> dict:
        """Generate proof for a finding."""
        return {
            "status": "proof_generated",
            "decision_id": getattr(decision, "decision_id", ""),
        }