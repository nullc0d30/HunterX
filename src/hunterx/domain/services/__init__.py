# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Domain services.

Domain services encode business rules that do not naturally belong to a single
entity: planning, correlation, deduplication and risk scoring. The concrete
implementations live in :mod:`hunterx.engines`; these interfaces keep the
dependency direction pointing inward.
"""

from __future__ import annotations

from hunterx.domain.services.correlator import CorrelationGroup, CorrelatorService
from hunterx.domain.services.deduplicator import DeduplicatorService
from hunterx.domain.services.planner import Plan, PlannedStep, PlannerService
from hunterx.domain.services.risk import RiskScorerService

__all__ = [
    "PlannerService",
    "PlannedStep",
    "Plan",
    "CorrelatorService",
    "CorrelationGroup",
    "DeduplicatorService",
    "RiskScorerService",
]
