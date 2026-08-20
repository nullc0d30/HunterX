# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Enums for the autonomous model-driven attack loop."""

from __future__ import annotations

from enum import StrEnum


class ModelHypothesisStatus(StrEnum):
    """Lifecycle of a model-generated attack hypothesis.

    A hypothesis is only ever actionable while it carries real scheduled work;
    a validated hypothesis is a finding that feeds the next reasoning round —
    never a loop-termination condition.
    """

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    QUEUED = "queued"
    EXECUTED = "executed"
    SUPPORTED = "supported"
    CONTRADICTED = "contradicted"
    VALIDATED = "validated"
    DISPROVED = "disproved"
    REJECTED = "rejected"
    EXHAUSTED = "exhausted"


class AttackerCompletion(StrEnum):
    """How the autonomous attack loop finished.

    ``EXHAUSTED`` is the only genuine-completion verdict: no unexplored
    surfaces, no pending tasks, no pending hypotheses, no model-generated
    paths and dynamic discovery exhausted. Resource ceilings (cycle counts,
    hypothesis caps, provider retry exhaustion) are never reported as
    completion — they are ``RESOURCE_LIMIT``.
    """

    EXHAUSTED = "exhausted"
    RESOURCE_LIMIT = "resource_limit"
    MODEL_UNAVAILABLE = "model_unavailable"
    BLOCKED = "blocked"
    STOPPED = "stopped"


class ModelFailureReason(StrEnum):
    """Why the connected model could not produce hypotheses."""

    TIMEOUT = "timeout"
    INVALID_OUTPUT = "invalid_output"
    MALFORMED_HYPOTHESES = "malformed_hypotheses"
    UNAVAILABLE = "unavailable"
    PROVIDER_LIMIT = "provider_limit"
    NONE = "none"


__all__ = ["AttackerCompletion", "ModelFailureReason", "ModelHypothesisStatus"]
