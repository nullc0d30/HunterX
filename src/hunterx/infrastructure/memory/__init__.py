# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory repository adapters.

Reference implementations of every domain repository port that keep the
platform runnable with zero external services. Used by the platform
composition root as the default persistence backend, by development and by
the test suite.

Modules:
    - :mod:`repositories` — core entity repositories (mission, finding, ...).
    - :mod:`planning` — mission planning repositories.
    - :mod:`factory` — Tool Integration Factory repositories.
"""

from __future__ import annotations

from hunterx.infrastructure.memory.factory import (
    InMemoryPackTemplateRepository,
    InMemoryToolPackRepository,
    build_in_memory_factory_repositories,
)
from hunterx.infrastructure.memory.planning import (
    InMemoryCheckpointRepository,
    InMemoryMissionPlanRepository,
    InMemoryMissionProfileRepository,
    InMemoryMissionTemplateRepository,
    InMemoryMissionTimelineRepository,
    build_in_memory_planning_repositories,
)
from hunterx.infrastructure.memory.repositories import (
    InMemoryAssetRepository,
    InMemoryFindingRepository,
    InMemoryMissionRepository,
    InMemoryReportRepository,
    InMemoryScanRepository,
    InMemoryTargetRepository,
    build_in_memory_repositories,
)

__all__ = [
    "InMemoryMissionRepository",
    "InMemoryFindingRepository",
    "InMemoryTargetRepository",
    "InMemoryScanRepository",
    "InMemoryAssetRepository",
    "InMemoryReportRepository",
    "build_in_memory_repositories",
    "InMemoryMissionProfileRepository",
    "InMemoryMissionTemplateRepository",
    "InMemoryMissionPlanRepository",
    "InMemoryCheckpointRepository",
    "InMemoryMissionTimelineRepository",
    "build_in_memory_planning_repositories",
    "InMemoryPackTemplateRepository",
    "InMemoryToolPackRepository",
    "build_in_memory_factory_repositories",
]
