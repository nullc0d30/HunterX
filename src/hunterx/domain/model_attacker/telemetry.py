# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Machine-readable telemetry for the autonomous attack loop.

The invariants here are testable: for any mission with remaining applicable
attack surface, ``validated_findings > 0`` and ``post_finding_model_calls > 0``
must both hold — a finding must never terminate the loop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackerTelemetry:
    """Running counters and state of the model-driven attack loop."""

    model_calls: int = 0
    hypotheses_generated: int = 0
    hypotheses_accepted: int = 0
    hypotheses_rejected: int = 0
    hypotheses_exhausted: int = 0
    model_generated_tasks: int = 0
    model_task_execution_count: int = 0
    model_feedback_events: int = 0
    new_attack_paths: int = 0
    finding_events: int = 0
    post_finding_model_calls: int = 0
    remaining_hypotheses: int = 0
    remaining_attack_tasks: int = 0
    completion_reason: str = ""
    model_failures: int = 0
    model_failure_reason: str = ""
    validated_findings: int = 0
    total_findings: int = 0
    cycles: int = 0
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize telemetry to a JSON-safe mapping."""
        return {
            "model_calls": self.model_calls,
            "hypotheses_generated": self.hypotheses_generated,
            "hypotheses_accepted": self.hypotheses_accepted,
            "hypotheses_rejected": self.hypotheses_rejected,
            "hypotheses_exhausted": self.hypotheses_exhausted,
            "model_generated_tasks": self.model_generated_tasks,
            "model_task_execution_count": self.model_task_execution_count,
            "model_feedback_events": self.model_feedback_events,
            "new_attack_paths": self.new_attack_paths,
            "finding_events": self.finding_events,
            "post_finding_model_calls": self.post_finding_model_calls,
            "remaining_hypotheses": self.remaining_hypotheses,
            "remaining_attack_tasks": self.remaining_attack_tasks,
            "completion_reason": self.completion_reason,
            "model_failures": self.model_failures,
            "model_failure_reason": self.model_failure_reason,
            "validated_findings": self.validated_findings,
            "total_findings": self.total_findings,
            "cycles": self.cycles,
            **self.extras,
        }


__all__ = ["AttackerTelemetry"]
