# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Mastery — the Sprint 025 knowledge and decision layer.

Transforms HunterX from "an orchestrator that can execute security tools"
into "a professional security operator that understands and correctly uses
every integrated tool". Composes the Tool Intelligence Platform (TIP) with
master profiles, a relationship graph, data-driven playbooks, mission-aware
selection, target-specific tool history, dataset provenance, parser
regression and result replay.
"""

from __future__ import annotations

from hunterx.domain.tool_mastery import (
    ToolCoverageReport,
    ToolDataset,
    ToolHistoryEntry,
    ToolMasterProfile,
    ToolPlaybook,
    ToolRelationship,
)
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.mastery.arsenal import UniversalSecurityArsenal
from hunterx.tools.mastery.coverage import ToolCoverageEngine
from hunterx.tools.mastery.datasets import ToolDatasetRegistry
from hunterx.tools.mastery.history import ToolHistory
from hunterx.tools.mastery.knowledge_fixtures import ToolKnowledgeFixtureRegistry
from hunterx.tools.mastery.playbooks import ToolPlaybookEngine
from hunterx.tools.mastery.registry import ToolMasteryRegistry
from hunterx.tools.mastery.regression import ParserRegressionEngine
from hunterx.tools.mastery.relationships import ToolRelationshipGraph
from hunterx.tools.mastery.replay import ToolResultReplay
from hunterx.tools.mastery.selection import MissionAwareToolSelector
from hunterx.tools.mastery.versioning import ToolVersionAwareness

__all__ = [
    "ToolMasteryAPI",
    "ToolMasteryRegistry",
    "ToolKnowledgeFixtureRegistry",
    "ToolRelationshipGraph",
    "ToolPlaybookEngine",
    "MissionAwareToolSelector",
    "ToolHistory",
    "ToolCoverageEngine",
    "ToolDatasetRegistry",
    "ParserRegressionEngine",
    "ToolResultReplay",
    "ToolVersionAwareness",
    "UniversalSecurityArsenal",
    "ToolMasterProfile",
    "ToolRelationship",
    "ToolPlaybook",
    "ToolDataset",
    "ToolHistoryEntry",
    "ToolCoverageReport",
]
