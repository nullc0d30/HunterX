# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Adaptive mission state machine.

Explicit, event-driven transitions between :class:`MissionState` values. The
canonical flow:

CREATED → SCOPING → DISCOVERY → ENUMERATION → MAPPING → ANALYSIS →
HYPOTHESIS_GENERATION → VALIDATION → PROOF → REASSESSMENT → REPORTING →
COMPLETED

with PAUSED / BLOCKED / FAILED / CANCELLED as exceptional states reachable
from any active state.
"""

from __future__ import annotations

from hunterx.domain.adaptive_mission_planning.enums import MissionState


class InvalidMissionStateTransitionError(Exception):
    """Raised when a transition is not allowed."""


#: Allowed state transitions.
_ALLOWED: dict[MissionState, frozenset[MissionState]] = {
    MissionState.CREATED: frozenset(
        {MissionState.SCOPING, MissionState.CANCELLED, MissionState.FAILED}
    ),
    MissionState.SCOPING: frozenset(
        {
            MissionState.DISCOVERY,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.DISCOVERY: frozenset(
        {
            MissionState.ENUMERATION,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.ENUMERATION: frozenset(
        {
            MissionState.MAPPING,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.MAPPING: frozenset(
        {
            MissionState.ANALYSIS,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.ANALYSIS: frozenset(
        {
            MissionState.HYPOTHESIS_GENERATION,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.HYPOTHESIS_GENERATION: frozenset(
        {
            MissionState.VALIDATION,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.VALIDATION: frozenset(
        {
            MissionState.PROOF,
            MissionState.REASSESSMENT,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.PROOF: frozenset(
        {
            MissionState.REASSESSMENT,
            MissionState.REPORTING,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.REASSESSMENT: frozenset(
        {
            MissionState.DISCOVERY,
            MissionState.ENUMERATION,
            MissionState.MAPPING,
            MissionState.ANALYSIS,
            MissionState.HYPOTHESIS_GENERATION,
            MissionState.VALIDATION,
            MissionState.PROOF,
            MissionState.REPORTING,
            MissionState.COMPLETED,
            MissionState.PAUSED,
            MissionState.BLOCKED,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.REPORTING: frozenset({MissionState.COMPLETED, MissionState.PAUSED, MissionState.FAILED}),
    MissionState.PAUSED: frozenset(
        {
            MissionState.REASSESSMENT,
            MissionState.DISCOVERY,
            MissionState.ENUMERATION,
            MissionState.MAPPING,
            MissionState.ANALYSIS,
            MissionState.HYPOTHESIS_GENERATION,
            MissionState.VALIDATION,
            MissionState.PROOF,
            MissionState.REPORTING,
            MissionState.CANCELLED,
            MissionState.FAILED,
        }
    ),
    MissionState.BLOCKED: frozenset({MissionState.PAUSED, MissionState.REASSESSMENT, MissionState.CANCELLED, MissionState.FAILED}),
    MissionState.COMPLETED: frozenset(),
    MissionState.FAILED: frozenset(),
    MissionState.CANCELLED: frozenset(),
}


def can_transition(current: MissionState, target: MissionState) -> bool:
    """Return ``True`` when the transition is allowed."""
    return target in _ALLOWED[current]


def allowed_targets(current: MissionState) -> frozenset[MissionState]:
    """Return every state reachable from ``current``."""
    return _ALLOWED[current]


def assert_transition(current: MissionState, target: MissionState) -> None:
    """Raise :class:`InvalidMissionStateTransitionError` when not allowed."""
    if not can_transition(current, target):
        raise InvalidMissionStateTransitionError(
            f"mission state '{current.value}' cannot transition to '{target.value}'"
        )


def _state(value: str) -> MissionState:
    for member in MissionState:
        if member.value == value:
            return member
    raise InvalidMissionStateTransitionError(f"unknown mission state '{value}'")
