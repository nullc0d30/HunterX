# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Core engine.

The Core Engine is the runtime aggregate of the platform: it holds every
engine, manager, registry and v7 facade (TIP, Tool Integration SDK,
Tool Integration Factory, Mission Planning) and exposes a single entry point
for applications (API/CLI/daemons). Components are injected via the
constructor so the engine can be assembled from the platform composition root
or from test doubles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hunterx.engines.correlation import TargetCorrelator
from hunterx.engines.mission import MissionEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.engines.planner import DeterministicPlanner
from hunterx.engines.reasoning import ReasoningEngine
from hunterx.engines.report import ReportEngine
from hunterx.engines.risk import DefaultRiskScorer
from hunterx.engines.workflow import WorkflowEngine
from hunterx.reporting.renderers import Renderer
from hunterx.tools.factory.api import ToolIntegrationFactory
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine

if TYPE_CHECKING:
    from hunterx.engines.target_intelligence.engine import TargetIntelligenceEngine


@dataclass(slots=True)
class CoreEngine:
    """Root facade aggregating all platform engines and v7 facades.

    Attributes:
        mission_engine: mission lifecycle orchestration.
        workflow_engine: workflow definition loading and execution.
        planner: deterministic mission planning.
        correlator: finding correlation.
        risk_scorer: finding risk scoring.
        reasoning_engine: AI-assisted analysis.
        report_engine: report assembly and rendering.
        renderers: registered report renderers.
        tip: Tool Intelligence Platform facade.
        execution_engine: Tool Integration SDK execution engine.
        tool_factory: Tool Integration Factory facade.
        mission_planning: mission planning engine facade.
        target_intelligence: Adaptive Target Intelligence engine facade.

    """

    mission_engine: MissionEngine
    workflow_engine: WorkflowEngine
    planner: DeterministicPlanner = field(default_factory=DeterministicPlanner)
    correlator: TargetCorrelator = field(default_factory=TargetCorrelator)
    risk_scorer: DefaultRiskScorer = field(default_factory=DefaultRiskScorer)
    reasoning_engine: ReasoningEngine | None = None
    report_engine: ReportEngine | None = None
    renderers: list[Renderer] = field(default_factory=list)
    tip: ToolIntelligenceAPI | None = None
    execution_engine: ExecutionEngine | None = None
    tool_factory: ToolIntegrationFactory | None = None
    mission_planning: MissionPlanningAPI | None = None
    target_intelligence: TargetIntelligenceEngine | None = None

    def register_renderer(self, renderer: Renderer) -> None:
        """Register a renderer and, if the report engine exists, attach it."""
        self.renderers.append(renderer)
        if self.report_engine is not None:
            self.report_engine.register_renderer(renderer)

    def workflows_available(self) -> list[str]:
        """Return the names of registered workflows."""
        return self.workflow_engine.list()
