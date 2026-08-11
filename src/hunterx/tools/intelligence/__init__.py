# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform (TIP).

The intelligence layer of HunterX v7. TIP knows *about* tools — what they do,
what they need, what they produce, how they relate — without ever executing
them. Subsystems (planner, AI engine, workflow engine, CLI, API) query TIP
through :class:`ToolIntelligenceAPI` (the facade) or the individual engines.

Engines
=======
- ``ToolIntelligenceRegistry`` — metadata / knowledge / capability /
  compatibility / runtime state stores.
- ``ToolTaxonomy`` — canonical category tree and capability vocabulary.
- ``CapabilityEngine`` — capability definitions and provider lookups.
- ``DependencyEngine`` — tool-to-tool and capability-to-tool resolution.
- ``CompatibilityEngine`` — OS / architecture / runtime environment checks.
- ``ToolSelectionEngine`` — criteria-based best-fit ranking.
- ``ToolRecommendationEngine`` — best / alternative / fallback recommendations.
- ``ToolStateMachine`` — lifecycle state transitions.
- ``ToolLifecycleManager`` — register, install, verify, deprecate, ...
- ``ToolHealthMonitor`` — reliability and availability tracking.
- ``ToolPerformanceAnalyzer`` — duration / finding / cost history.
- ``ToolValidationFramework`` — configuration sanity checks.
- ``ToolDocumentationGenerator`` — per-tool Markdown reference pages.
- ``ToolAIInterface`` — question/answer bridge for the AI engine.
"""

from __future__ import annotations

from hunterx.tools.intelligence.ai import ToolAIAnswer, ToolAIInterface, build_recommendation_prompt
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.capability import CapabilityEngine
from hunterx.tools.intelligence.compatibility import CompatibilityEngine, CompatibilityResult
from hunterx.tools.intelligence.correlation import EvidenceCorrelator
from hunterx.tools.intelligence.dependency import DependencyEngine
from hunterx.tools.intelligence.docs import ToolDocumentationGenerator
from hunterx.tools.intelligence.enforcement import ToolEnforcementEngine
from hunterx.tools.intelligence.escalation import EscalationEngine
from hunterx.tools.intelligence.health import ToolHealthMonitor
from hunterx.tools.intelligence.layer import ToolIntelligenceLayer
from hunterx.tools.intelligence.lifecycle import ToolLifecycleManager
from hunterx.tools.intelligence.parsers import NormalizerRegistry, ParserRegistry, ToolRuntimeRegistry
from hunterx.tools.intelligence.performance import ToolPerformanceAnalyzer
from hunterx.tools.intelligence.planner import ToolSequencePlanner
from hunterx.tools.intelligence.recommendation import ToolRecommendationEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.reliability import ToolReliabilityTracker
from hunterx.tools.intelligence.schema import (
    compatibility_from_dict,
    knowledge_from_dict,
    load_knowledge_file,
    metadata_from_dict,
    metadata_to_dict,
)
from hunterx.tools.intelligence.selection import ToolSelectionEngine
from hunterx.tools.intelligence.selector import ToolSelector
from hunterx.tools.intelligence.state import ToolStateMachine
from hunterx.tools.intelligence.target import TargetIntelligenceStore
from hunterx.tools.intelligence.taxonomy import ToolTaxonomy
from hunterx.tools.intelligence.validation import (
    ToolValidationFramework,
    ValidationFinding,
    ValidationReport,
    ValidationSeverity,
)
from hunterx.tools.intelligence.vocabulary import (
    CAPABILITY_ALIASES,
    CapabilityVocabulary,
)

__all__ = [
    "ToolAIAnswer",
    "ToolAIInterface",
    "build_recommendation_prompt",
    "ToolIntelligenceAPI",
    "CapabilityEngine",
    "CompatibilityEngine",
    "CompatibilityResult",
    "EvidenceCorrelator",
    "DependencyEngine",
    "ToolDocumentationGenerator",
    "ToolEnforcementEngine",
    "EscalationEngine",
    "ToolHealthMonitor",
    "ToolIntelligenceLayer",
    "ToolLifecycleManager",
    "NormalizerRegistry",
    "ParserRegistry",
    "ToolRuntimeRegistry",
    "ToolPerformanceAnalyzer",
    "ToolSequencePlanner",
    "ToolRecommendationEngine",
    "ToolIntelligenceRegistry",
    "ToolReliabilityTracker",
    "compatibility_from_dict",
    "knowledge_from_dict",
    "load_knowledge_file",
    "metadata_from_dict",
    "metadata_to_dict",
    "ToolSelector",
    "ToolSelectionEngine",
    "ToolStateMachine",
    "TargetIntelligenceStore",
    "ToolTaxonomy",
    "CapabilityVocabulary",
    "CAPABILITY_ALIASES",
    "ToolValidationFramework",
    "ValidationFinding",
    "ValidationReport",
    "ValidationSeverity",
]
