# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Autonomous model-driven attack loop (Phase 7).

Turns the connected model into an active participant in the real execution
loop: observation → reasoning → hypothesis generation → attack selection →
prioritization → probing → response analysis → verification → learning → new
hypotheses — until genuine attack-surface/hypothesis exhaustion. A validated
finding never terminates the mission; it expands the search.
"""

from hunterx.domain.model_attacker.dedup import hypothesis_fingerprint
from hunterx.domain.model_attacker.enums import AttackerCompletion, ModelHypothesisStatus
from hunterx.domain.model_attacker.exhaustion import classify_completion
from hunterx.domain.model_attacker.learning import LearningContext
from hunterx.domain.model_attacker.models import AttackPlan, ModelFeedbackEvent, ModelHypothesis
from hunterx.domain.model_attacker.reasoner import ModelReasoner, ReasonResult
from hunterx.domain.model_attacker.telemetry import AttackerTelemetry

__all__ = [
    "AttackPlan",
    "AttackerCompletion",
    "AttackerTelemetry",
    "LearningContext",
    "ModelFeedbackEvent",
    "ModelHypothesis",
    "ModelHypothesisStatus",
    "ModelReasoner",
    "ReasonResult",
    "classify_completion",
    "genuine_exhaustion",
    "hypothesis_fingerprint",
]
