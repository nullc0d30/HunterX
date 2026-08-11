# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Engine layer.

Engines orchestrate the platform's core capabilities: mission execution,
workflows, planning, correlation, reasoning and reporting. Engines depend on
the domain, application and shared layers and receive their collaborators
(ports) through constructors.
"""

from __future__ import annotations

from hunterx.engines.core import CoreEngine
from hunterx.engines.correlation import TargetCorrelator
from hunterx.engines.mission import MissionEngine
from hunterx.engines.mission_planning.api import MissionPlanningAPI
from hunterx.engines.mission_planning.checkpoints import CheckpointManager
from hunterx.engines.mission_planning.config import ConfigurationResolver
from hunterx.engines.mission_planning.engine import MissionPlanningEngine
from hunterx.engines.mission_planning.graph import ExecutionGraphBuilder
from hunterx.engines.mission_planning.planner import MissionPlanner
from hunterx.engines.mission_planning.profiles import MissionProfileEngine
from hunterx.engines.mission_planning.state import MissionPlanTransition, MissionStateMachine
from hunterx.engines.mission_planning.timeline import MissionTimeline
from hunterx.engines.planner import DeterministicPlanner
from hunterx.engines.report import ReportEngine
from hunterx.engines.risk import DefaultRiskScorer
from hunterx.engines.workflow import WorkflowDefinition, WorkflowEngine, WorkflowStep
from hunterx.tools.factory.api import ToolIntegrationFactory

__all__ = [
    "CoreEngine",
    "MissionEngine",
    "WorkflowEngine",
    "WorkflowDefinition",
    "WorkflowStep",
    "DeterministicPlanner",
    "TargetCorrelator",
    "DefaultRiskScorer",
    "ReportEngine",
    "MissionPlanningAPI",
    "MissionPlanningEngine",
    "MissionProfileEngine",
    "ConfigurationResolver",
    "MissionPlanner",
    "ExecutionGraphBuilder",
    "CheckpointManager",
    "MissionTimeline",
    "MissionStateMachine",
    "MissionPlanTransition",
    "ToolIntegrationFactory",
]
