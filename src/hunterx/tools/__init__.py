# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool adapters, parsers, normalizers, executor, intelligence (TIP) and SDK."""

from __future__ import annotations

from hunterx.tools.adapter import BaseTool, ToolContext, ToolOutput
from hunterx.tools.categories import AnalyzerTool, CrawlerTool, EnumeratorTool, ReporterTool, ScannerTool
from hunterx.tools.discovery import ToolDiscovery
from hunterx.tools.executor import ToolExecutor
from hunterx.tools.factory import (
    CompatibilityValidator,
    PackTemplateStore,
    ToolIntegrationFactory,
    ToolPackGeneratorEngine,
    ToolPackValidator,
    VersionResolver,
    default_generators,
)
from hunterx.tools.intelligence import (
    CapabilityEngine,
    CompatibilityEngine,
    DependencyEngine,
    ToolAIInterface,
    ToolDocumentationGenerator,
    ToolHealthMonitor,
    ToolIntelligenceAPI,
    ToolIntelligenceRegistry,
    ToolLifecycleManager,
    ToolPerformanceAnalyzer,
    ToolRecommendationEngine,
    ToolSelectionEngine,
    ToolStateMachine,
    ToolTaxonomy,
    ToolValidationFramework,
)
from hunterx.tools.normalizer import NormalizerEngine
from hunterx.tools.parser import Parser, ParserEngine
from hunterx.tools.sandbox import ToolSandboxPolicy
from hunterx.tools.sdk import (
    ExecutionContextBuilder,
    ExecutionEngine,
    ExecutionEventBus,
    ExecutionMonitor,
    ExecutionPipeline,
    ExecutionSandbox,
    ExecutionSession,
    OutputCollector,
    ResourceManager,
    ToolAdapter,
    ToolLockManager,
    ToolQueue,
)
from hunterx.tools.validation import ToolValidator

__all__ = [
    "BaseTool",
    "ToolOutput",
    "ToolContext",
    "ScannerTool",
    "CrawlerTool",
    "EnumeratorTool",
    "AnalyzerTool",
    "ReporterTool",
    "ParserEngine",
    "Parser",
    "NormalizerEngine",
    "ToolExecutor",
    "ToolDiscovery",
    "ToolValidator",
    "ToolSandboxPolicy",
    "ToolIntelligenceAPI",
    "ToolIntelligenceRegistry",
    "ToolTaxonomy",
    "CapabilityEngine",
    "DependencyEngine",
    "CompatibilityEngine",
    "ToolSelectionEngine",
    "ToolRecommendationEngine",
    "ToolStateMachine",
    "ToolLifecycleManager",
    "ToolHealthMonitor",
    "ToolPerformanceAnalyzer",
    "ToolValidationFramework",
    "ToolDocumentationGenerator",
    "ToolAIInterface",
    "ToolAdapter",
    "ExecutionContextBuilder",
    "ExecutionEngine",
    "ExecutionEventBus",
    "ExecutionMonitor",
    "ExecutionPipeline",
    "ExecutionSandbox",
    "ExecutionSession",
    "OutputCollector",
    "ResourceManager",
    "ToolLockManager",
    "ToolQueue",
    "ToolIntegrationFactory",
    "ToolPackGeneratorEngine",
    "CompatibilityValidator",
    "ToolPackValidator",
    "VersionResolver",
    "PackTemplateStore",
    "default_generators",
]
