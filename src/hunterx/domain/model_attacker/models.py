# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Models for the autonomous model-driven attack loop.

The hypothesis is the machine-readable hand-off from the connected model to the
real HunterX execution pipeline. The model's natural-language reasoning is
carried in ``reasoning_context`` but the actionable portion — capability,
surface, attack vector, strategy, expected signal, priority, confidence and
authentication context — is structured so every accepted hypothesis becomes a
real assessment task with no parallel fake path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.model_attacker.enums import ModelHypothesisStatus
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


@dataclass(frozen=True, slots=True)
class ModelHypothesis:
    """A structured, machine-readable attack hypothesis from the model."""

    hypothesis_id: str = field(default_factory=generate_id)
    capability: str = ""
    surface: str = ""            # endpoint URL
    attack_vector: str = ""      # parameter / path / header name
    attack_strategy: str = ""
    reasoning_context: str = ""
    expected_signal: str = ""
    priority: float = 0.5
    confidence: float = 0.5
    authentication_context: str = "anonymous"
    workflow_context: str = ""
    parent_hypothesis: str = ""
    status: ModelHypothesisStatus = ModelHypothesisStatus.PROPOSED
    fingerprint: str = ""
    created_at: str = field(default_factory=utcnow_iso)

    def with_status(self, status: ModelHypothesisStatus) -> ModelHypothesis:
        """Return a copy with ``status`` updated."""
        return _replace_status(self, status)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the hypothesis to a JSON-safe mapping."""
        return {
            "hypothesis_id": self.hypothesis_id,
            "capability": self.capability,
            "surface": self.surface,
            "attack_vector": self.attack_vector,
            "attack_strategy": self.attack_strategy,
            "reasoning_context": self.reasoning_context,
            "expected_signal": self.expected_signal,
            "priority": self.priority,
            "confidence": self.confidence,
            "authentication_context": self.authentication_context,
            "workflow_context": self.workflow_context,
            "parent_hypothesis": self.parent_hypothesis,
            "status": self.status.value,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at,
        }


def _replace_status(hypothesis: ModelHypothesis, status: ModelHypothesisStatus) -> ModelHypothesis:
    from dataclasses import replace

    return replace(hypothesis, status=status)


@dataclass(frozen=True, slots=True)
class AttackPlan:
    """A model hypothesis mapped onto a real assessment task.

    ``task_id`` is populated when the hypothesis is queued through the attack-
    surface service; the task then runs through the ordinary capability
    execution engine — the same pipeline as every discovery-derived task.
    """

    plan_id: str = field(default_factory=generate_id)
    hypothesis_id: str = ""
    capability: str = ""
    surface: str = ""
    vector: str = ""
    strategy: str = ""
    task_id: str = ""
    queued_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the attack plan to a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "hypothesis_id": self.hypothesis_id,
            "capability": self.capability,
            "surface": self.surface,
            "vector": self.vector,
            "strategy": self.strategy,
            "task_id": self.task_id,
            "queued_at": self.queued_at,
        }


@dataclass(frozen=True, slots=True)
class ModelFeedbackEvent:
    """One observation fed back to the model's reasoning context."""

    event_id: str = field(default_factory=generate_id)
    hypothesis_id: str = ""
    capability: str = ""
    surface: str = ""
    signal: str = ""
    supported: bool = False
    contradicted: bool = False
    finding: bool = False
    recorded_at: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the feedback event to a JSON-safe mapping."""
        return {
            "event_id": self.event_id,
            "hypothesis_id": self.hypothesis_id,
            "capability": self.capability,
            "surface": self.surface,
            "signal": self.signal,
            "supported": self.supported,
            "contradicted": self.contradicted,
            "finding": self.finding,
            "recorded_at": self.recorded_at,
        }


__all__ = ["AttackPlan", "ModelFeedbackEvent", "ModelHypothesis"]
