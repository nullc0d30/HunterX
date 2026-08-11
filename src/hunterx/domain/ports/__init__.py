# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Ports (abstract interfaces).

Ports define the contracts that infrastructure adapters implement. Domain and
application layers depend only on these abstractions; concrete adapters
(``hunterx.infrastructure``) are wired in at composition time. This keeps the
platform swappable and testable.
"""

from __future__ import annotations

from hunterx.domain.ports.messaging import (
    CachePort,
    EventBusPort,
    QueuePort,
)
from hunterx.domain.ports.mission_planning import (
    CheckpointRepository,
    MissionPlanRepository,
    MissionProfileRepository,
    MissionTemplateRepository,
    MissionTimelineRepository,
)
from hunterx.domain.ports.repositories import (
    AssetRepository,
    FindingRepository,
    MissionRepository,
    ReportRepository,
    ScanRepository,
    TargetRepository,
)
from hunterx.domain.ports.services import (
    AIPort,
    PluginRegistryPort,
    SandboxPort,
    SecretsPort,
    TelemetryPort,
    ToolRegistryPort,
)
from hunterx.domain.ports.stores import (
    EvidenceStore,
    KnowledgeGraphPort,
    ObjectStorePort,
)
from hunterx.domain.ports.tool_factory import (
    PackTemplateRepository,
    ToolPackRepository,
)
from hunterx.domain.ports.tool_intelligence import ToolIntelligencePort

__all__ = [
    "MissionRepository",
    "FindingRepository",
    "TargetRepository",
    "ScanRepository",
    "AssetRepository",
    "ReportRepository",
    "ObjectStorePort",
    "EvidenceStore",
    "KnowledgeGraphPort",
    "EventBusPort",
    "QueuePort",
    "CachePort",
    "SecretsPort",
    "SandboxPort",
    "AIPort",
    "TelemetryPort",
    "PluginRegistryPort",
    "ToolRegistryPort",
    "ToolIntelligencePort",
    "MissionProfileRepository",
    "MissionTemplateRepository",
    "MissionPlanRepository",
    "CheckpointRepository",
    "MissionTimelineRepository",
    "PackTemplateRepository",
    "ToolPackRepository",
]
