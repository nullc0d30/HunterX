# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Genuine-exhaustion semantics for the autonomous attack loop.

The loop may terminate as ``EXHAUSTED`` only when every applicable work source
is genuinely empty: unexplored attack surfaces, pending capability tasks,
pending verification, accepted-but-unexecuted hypotheses, model-generated
paths and dynamic discovery. Model inactivity alone is not exhaustion, a
finding is not exhaustion, and a fixed budget/cycle/token ceiling is
``RESOURCE_LIMIT`` — never ``COMPLETE``.
"""

from __future__ import annotations


def genuine_exhaustion(
    *,
    queue_exhausted: bool,
    pending_hypotheses: int,
    pending_model_tasks: int,
    discovery_exhausted: bool,
    surfaces_pending: bool,
) -> bool:
    """Return ``True`` only when every work source is genuinely empty."""
    return (
        queue_exhausted
        and pending_hypotheses == 0
        and pending_model_tasks == 0
        and discovery_exhausted
        and not surfaces_pending
    )


def classify_completion(
    *,
    exhausted: bool,
    resource_ceiling_hit: bool,
    model_unavailable: bool,
) -> str:
    """Return the truthful completion reason for the loop.

    A resource ceiling or an unavailable model while work remains is never
    reported as completion — it is ``RESOURCE_LIMIT`` / ``MODEL_UNAVAILABLE``.
    """
    if exhausted:
        return "exhausted"
    if model_unavailable:
        return "model_unavailable"
    if resource_ceiling_hit:
        return "resource_limit"
    return "stopped"


__all__ = ["classify_completion", "genuine_exhaustion"]
