# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Application-layer data transfer objects.

DTOs are plain validated inputs for use-case services. They shield the domain
model from API/CLI request shapes.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class CreateMissionRequest:
    """Input for creating a mission."""

    name: str
    workflow: str
    targets: list[str] = field(default_factory=list)
    kind: str = "scan"
    priority: str = "medium"
    config: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class CreateFindingRequest:
    """Input for persisting a normalized finding."""

    title: str
    severity: str
    target: str
    tool: str
    mission_id: str | None = None
    description: str = ""
    risk_score: float | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class CreateReportRequest:
    """Input for creating a report."""

    mission_id: str
    kind: str = "technical"
    title: str = ""
    summary: str = ""
