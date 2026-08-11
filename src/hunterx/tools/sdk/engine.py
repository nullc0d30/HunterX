# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution engine.

Composition root of the Tool Integration SDK. Assembles the sandbox, resource
manager, timeout/retry managers, lock manager, cache, queue, scheduler,
dependency resolver, installer, version manager, health checker, monitor and
event bus into a single entry point for running tool executions.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.execution import ExecutionContext
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.sdk.adapter import AdapterFactory, ToolAdapter
from hunterx.tools.sdk.cache import ExecutionCache
from hunterx.tools.sdk.dependencies import DependencyResolver
from hunterx.tools.sdk.events import ExecutionEventBus
from hunterx.tools.sdk.health import HealthChecker
from hunterx.tools.sdk.installer import InstallationManager
from hunterx.tools.sdk.locks import ToolLockManager
from hunterx.tools.sdk.monitor import ExecutionMonitor
from hunterx.tools.sdk.parallel import ParallelExecutionManager
from hunterx.tools.sdk.pipeline import ExecutionPipeline, PipelineResult
from hunterx.tools.sdk.plugin import ExecutionPluginManager
from hunterx.tools.sdk.queue import ToolQueue
from hunterx.tools.sdk.resources import ResourceManager
from hunterx.tools.sdk.retry import RetryManager
from hunterx.tools.sdk.sandbox import ExecutionSandbox
from hunterx.tools.sdk.scheduler import TaskScheduler
from hunterx.tools.sdk.timeout import TimeoutManager
from hunterx.tools.sdk.version import VersionManager


class ExecutionEngine:
    """Top-level entry point for the Tool Integration SDK.

    Usage::

        engine = ExecutionEngine(intelligence=tip_api.registry)
        engine.register_adapter("nmap", "hunterx_tools.nmap:NmapAdapter")
        engine.install("nmap", version="7.94")
        result = engine.execute(context).result
    """

    def __init__(
        self,
        *,
        intelligence: ToolIntelligenceRegistry | None = None,
        max_parallel_jobs: int = 0,
        max_queue_size: int = 0,
        cache_ttl_s: int = 0,
        adapters: dict[str, ToolAdapter | str] | None = None,
    ) -> None:
        self.sandbox = ExecutionSandbox()
        self.resources = ResourceManager(max_parallel_jobs=max_parallel_jobs, max_queue_size=max_queue_size)
        self.timeout = TimeoutManager()
        self.retry = RetryManager()
        self.locks = ToolLockManager()
        self.cache = ExecutionCache(ttl_s=cache_ttl_s)
        self.queue = ToolQueue(capacity=max_queue_size or 0)
        self.versions = VersionManager()
        self.installer = InstallationManager()
        self.health = HealthChecker(self.installer, self.versions)
        self.monitor = ExecutionMonitor()
        self.events = ExecutionEventBus()
        self.plugins = ExecutionPluginManager()
        self.parallel = ParallelExecutionManager(max_workers=max_parallel_jobs)
        self.scheduler = TaskScheduler(self.queue, self.resources)

        self._intelligence = intelligence or ToolIntelligenceRegistry()
        self._resolver = DependencyResolver(self._intelligence, self.installer)
        self._adapters: dict[str, ToolAdapter] = {}
        self._factory = AdapterFactory()
        self._pipelines: dict[str, ExecutionPipeline] = {}

        if adapters:
            for tool_id, adapter in adapters.items():
                self.register_adapter(tool_id, adapter)

    # -- registration ---------------------------------------------------------

    def register_adapter(self, tool_id: str, adapter: ToolAdapter | str) -> ToolAdapter:
        """Register an adapter instance or entrypoint for ``tool_id``.

        Legacy :class:`BaseTool` instances are wrapped in a
        :class:`LegacyToolBridge` automatically.
        """
        if isinstance(adapter, str):
            instance = self._factory.create(adapter)
        elif isinstance(adapter, ToolAdapter):
            instance = adapter
        else:
            from hunterx.tools.adapter import BaseTool

            if isinstance(adapter, BaseTool):
                instance = self._factory.bridge(adapter)
            else:
                raise TypeError(f"'{adapter!r}' is not a tool adapter.")
        self._adapters[tool_id] = instance
        self._pipelines[tool_id] = self._build_pipeline(instance)
        capabilities = [
            cap for cap in getattr(instance.descriptor, "capabilities", ()) if isinstance(cap, str)
        ]
        if capabilities:
            self._register_capabilities(tool_id, capabilities)
        return instance

    def unregister_adapter(self, tool_id: str) -> None:
        """Remove an adapter and its pipeline."""
        self._adapters.pop(tool_id, None)
        self._pipelines.pop(tool_id, None)

    def adapter_for(self, tool_id: str) -> ToolAdapter | None:
        """Return the registered adapter, or ``None``."""
        return self._adapters.get(tool_id)

    # -- install / health -----------------------------------------------------

    def install(self, tool_id: str, *, version: str | None = None) -> None:
        """Install ``tool_id`` via its adapter's install hook (if registered)."""
        hook = getattr(self.adapter_for(tool_id), "installer", None)
        if hook is not None:
            self.installer.register(tool_id, hook)
        record = self.installer.install(tool_id, version)
        if record.error is None:
            self.versions.record(tool_id, record.version)

    def health_check(self, tool_id: str, *, requirement: str | None = None) -> bool:
        """Return ``True`` when ``tool_id`` is healthy and ready to run."""
        return self.health.check(tool_id, requirement=requirement).healthy

    def install_hook(self, tool_id: str, hook: Any) -> None:
        """Register an installation callable for ``tool_id`` directly."""
        self.installer.register(tool_id, hook)

    def health_probe(self, tool_id: str, probe: Any) -> None:
        """Register a health probe callable for ``tool_id``."""
        self.health.probe(tool_id, probe)

    # -- execution -------------------------------------------------------------

    def execute(self, context: ExecutionContext) -> PipelineResult:
        """Run one execution and return the pipeline outcome."""
        pipeline = self._pipeline_for(context.tool_id)
        return pipeline.run(context)

    def execute_batch(self, contexts: list[ExecutionContext]) -> list[PipelineResult]:
        """Run several contexts sequentially (use :meth:`submit` for concurrency)."""
        return [self.execute(context) for context in contexts]

    def submit(self, context: ExecutionContext) -> None:
        """Enqueue ``context`` for the scheduler to process."""
        self.queue.enqueue(context)

    def drain(self, runner: Any = None, *, max_items: int = 0) -> list[PipelineResult]:
        """Process queued executions; ``runner`` defaults to :meth:`execute`."""
        run = runner or self.execute
        return self.scheduler.drain(run, max_items=max_items)

    def run_parallel(self, contexts: list[ExecutionContext]) -> list[PipelineResult]:
        """Run ``contexts`` concurrently under the parallel-jobs cap."""
        futures = [self.parallel.submit(self.execute, context) for context in contexts]
        return self.parallel.collect(futures)

    def shutdown(self) -> None:
        """Release parallel workers."""
        self.parallel.shutdown()

    # -- internals ---------------------------------------------------------------

    def _build_pipeline(self, adapter: ToolAdapter) -> ExecutionPipeline:
        return ExecutionPipeline(
            adapter=adapter,
            sandbox=self.sandbox,
            resources=self.resources,
            timeout=self.timeout,
            retry=self.retry,
            dependencies=self._resolver,
            health=self.health,
            monitor=self.monitor,
            events=self.events,
        )

    def _pipeline_for(self, tool_id: str) -> ExecutionPipeline:
        pipeline = self._pipelines.get(tool_id)
        if pipeline is None:
            raise LookupError(f"no adapter registered for tool '{tool_id}'")
        return pipeline

    def _register_capabilities(self, tool_id: str, capabilities: list[str]) -> None:
        from hunterx.tools.sdk.capabilities import ExecutionCapabilityRegistry

        if not hasattr(self, "_capability_registry"):
            self._capability_registry = ExecutionCapabilityRegistry()
        self._capability_registry.register(tool_id, capabilities)
