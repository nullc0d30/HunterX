# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Planner domain service.

The planner decomposes a mission into an ordered, dependency-aware plan of
steps. Concrete planning strategies (deterministic workflows, AI-assisted)
implement this interface.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field

from hunterx.domain.entities import Mission


@dataclass(frozen=True, slots=True)
class PlannedStep:
    """A single unit of planned work.

    Attributes:
        step_id: stable step identifier.
        action: tool/plugin action to execute.
        target: target identifier.
        parameters: action parameters.
        depends_on: identifiers of steps that must finish first.

    """

    step_id: str
    action: str
    target: str
    parameters: dict[str, object] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Plan:
    """An ordered collection of planned steps.

    Attributes:
        steps: planned steps, ordered by execution sequence.

    """

    steps: tuple[PlannedStep, ...] = ()


class PlannerService(abc.ABC):
    """Contract for mission planning."""

    @abc.abstractmethod
    def plan(self, mission: Mission) -> Plan:
        """Decompose a mission into an ordered, dependency-aware plan."""
