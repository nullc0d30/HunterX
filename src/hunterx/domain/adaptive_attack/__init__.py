# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Aggressive, adaptive, multi-vector attack engine primitives.

Phase 2. This package provides the target-agnostic attack behavior layer that
runs on top of the Phase 1 attack-surface model:

    * adaptive rate control (:class:`AdaptiveRateController`) — a bounded state
      machine (NORMAL → AGGRESSIVE → THROTTLED → BACKING_OFF → RECOVERING →
      BLOCKED → RESUMING) driven purely by observed target feedback;
    * target feedback classification (:class:`FeedbackMonitor` +
      :class:`FeedbackClassifier`) — 429/403/5xx/timeout/connection/latency/WAF
      signals, never treated as mission completion;
    * multi-vector selection (:class:`VectorSelector`) — only vectors that
      apply to a discovered surface are scheduled;
    * bounded probe planning (:class:`AttackProbePlan` +
      :class:`AggressionProfile`) — baseline → probe → differential → stronger
      → verify with hard payload/mutation bounds;
    * generic workflow representation (:class:`AttackWorkflow`) — State A →
      Action → State B, never hardcoded application workflows.

Nothing here assumes a specific target technology, route, object model or
authentication flow. Defensive responses are feedback, never completion;
resource limits are limits; blocking is blocking.

Responsibilities
    * Classify every execution outcome into a canonical target-feedback signal.
    * Transition the attack state machine from observed behavior and derive
      bounded controls (aggression, pacing, concurrency, backoff, retry).
    * Select only the attack vectors that apply to a discovered surface.
    * Build bounded probe plans with an explicit escalation ladder.
    * Represent multi-step behavior as generic states and transitions.

Dependencies
    * ``hunterx.domain.attack_surface`` (surface kinds, contexts, nodes).
    * ``hunterx.shared`` (identifiers, time) for stable identity and stamps.

Extension points
    * :class:`VectorSelector` — register new kind → vector mappings.
    * :class:`AttackControlConfig` — tune bounded control thresholds.
    * :class:`AggressionProfile` — bound payload/mutation depth per tier.
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
