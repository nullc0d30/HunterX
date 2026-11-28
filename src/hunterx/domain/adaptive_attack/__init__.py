# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Aggressive, adaptive, multi-vector attack engine primitives.

This package provides the target-agnostic attack behavior layer that runs on top of the attack-surface model.
"""

from __future__ import annotations

from hunterx.domain.adaptive_attack.control import AdaptiveRateController, AttackControlConfig
from hunterx.domain.adaptive_attack.enums import (
    AggressionLevel,
    AttackOutcome,
    AttackState,
    AttackVector,
    FeedbackSignal,
)
from hunterx.domain.adaptive_attack.feedback import FeedbackClassifier, FeedbackMonitor, FeedbackSample
from hunterx.domain.adaptive_attack.probe import (
    AggressionProfile,
    AttackProbePlan,
    ProbeStep,
    bounded_mutations,
    bounded_payloads,
    profile_for,
)
from hunterx.domain.adaptive_attack.vector import VectorSelector
from hunterx.domain.adaptive_attack.workflow import (
    AttackWorkflow,
    AttackWorkflowState,
    AttackWorkflowTransition,
    build_workflow_from_attributes,
)

__all__ = [
    "AdaptiveRateController",
    "AggressionLevel",
    "AggressionProfile",
    "AttackControlConfig",
    "AttackOutcome",
    "AttackProbePlan",
    "AttackState",
    "AttackVector",
    "AttackWorkflow",
    "AttackWorkflowState",
    "AttackWorkflowTransition",
    "FeedbackClassifier",
    "FeedbackMonitor",
    "FeedbackSample",
    "FeedbackSignal",
    "ProbeStep",
    "VectorSelector",
    "build_workflow_from_attributes",
    "bounded_mutations",
    "bounded_payloads",
    "profile_for",
]
