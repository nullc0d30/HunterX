# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""HunterX Tool Integration SDK.

The single supported way to integrate external security tools with HunterX.
Tools implement a :class:`~hunterx.tools.sdk.adapter.ToolAdapter` and are
executed by :class:`~hunterx.tools.sdk.engine.ExecutionEngine`, which drives
the full lifecycle: register, install, validate, verify, prepare, execute,
monitor, collect, validate output, normalize, store, events and cleanup.
"""

from __future__ import annotations

from hunterx.tools.sdk.adapter import AdapterFactory, LegacyToolBridge, ToolAdapter
from hunterx.tools.sdk.cache import ExecutionCache
from hunterx.tools.sdk.capabilities import ExecutionCapabilityRegistry
from hunterx.tools.sdk.context import ExecutionContextBuilder, ExecutionIDFactory
from hunterx.tools.sdk.dependencies import DependencyResolver
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.events import ExecutionEventBus
from hunterx.tools.sdk.health import HealthChecker
from hunterx.tools.sdk.installer import InstallationManager
from hunterx.tools.sdk.locks import ToolLockManager
from hunterx.tools.sdk.monitor import ExecutionMonitor
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.sdk.parallel import ParallelExecutionManager
from hunterx.tools.sdk.pipeline import ExecutionPipeline, PipelineResult
from hunterx.tools.sdk.plugin import ExecutionPluginManager, LoadedPlugin
from hunterx.tools.sdk.queue import QueueItem, ToolQueue
from hunterx.tools.sdk.resources import ResourceManager, ResourceUsage
from hunterx.tools.sdk.retry import RetryManager
from hunterx.tools.sdk.sandbox import ExecutionSandbox
from hunterx.tools.sdk.scheduler import TaskScheduler
from hunterx.tools.sdk.session import ExecutionArtifact, ExecutionSession
from hunterx.tools.sdk.timeout import TimeoutManager
from hunterx.tools.sdk.version import VersionManager

__all__ = [
    "AdapterFactory",
    "DependencyResolver",
    "ExecutionArtifact",
    "ExecutionCache",
    "ExecutionCapabilityRegistry",
    "ExecutionContextBuilder",
    "ExecutionEngine",
    "ExecutionEventBus",
    "ExecutionIDFactory",
    "ExecutionMonitor",
    "ExecutionPipeline",
    "ExecutionPluginManager",
    "ExecutionSandbox",
    "ExecutionSession",
    "HealthChecker",
    "InstallationManager",
    "LegacyToolBridge",
    "LoadedPlugin",
    "OutputCollector",
    "ParallelExecutionManager",
    "PipelineResult",
    "QueueItem",
    "ResourceManager",
    "ResourceUsage",
    "RetryManager",
    "TaskScheduler",
    "TimeoutManager",
    "ToolAdapter",
    "ToolLockManager",
    "ToolQueue",
    "VersionManager",
]
