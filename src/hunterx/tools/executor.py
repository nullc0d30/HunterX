# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool executor.

The executor is the runtime that runs tool adapters by name and returns their
normalized output. It also implements the executor contract the workflow
engine depends on, wiring workflow actions to concrete tools.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.exceptions import ToolExecutionError, ToolNotFoundError
from hunterx.domain.ports.services import ToolRegistryPort
from hunterx.domain.tools import ToolDescriptor
from hunterx.shared.result import Failure, Result, Success
from hunterx.tools.adapter import BaseTool, ToolContext, ToolOutput


class ToolExecutor:
    """Run registered tools and expose their descriptors.

    Tools are registered through a :class:`ToolRegistryPort` (or directly)
    and executed by name. Output is always a :class:`ToolOutput`.
    """

    def __init__(self, registry: ToolRegistryPort) -> None:
        self._registry = registry
        self._tools: dict[str, BaseTool] = {}

    def register_tool(self, name: str, tool: BaseTool, descriptor: ToolDescriptor | None = None) -> None:
        """Register a tool instance under ``name``."""
        self._tools[name] = tool
        self._registry.register(descriptor or tool.descriptor)

    def register_descriptor(self, descriptor: ToolDescriptor) -> None:
        """Register a descriptor without a backing instance."""
        self._registry.register(descriptor)

    def get(self, name: str) -> BaseTool:
        """Return a tool by name or raise :class:`ToolNotFoundError`."""
        tool = self._tools.get(name)
        if tool is None:
            raise ToolNotFoundError(name)
        return tool

    def list(self) -> list[ToolDescriptor]:
        """Return descriptors of all registered tools."""
        return self._registry.list()

    def execute(
        self,
        tool: str,
        target: str,
        parameters: dict[str, Any],
        *,
        mission_id: str = "",
        context: ToolContext | None = None,
    ) -> ToolOutput:
        """Run ``tool`` against ``target`` and return its output.

        This never raises for tool failures — errors are captured inside
        :class:`ToolOutput`.
        """
        try:
            adapter = self.get(tool)
        except ToolNotFoundError as exc:
            output = ToolOutput(error=str(exc))
            return output
        run_context = context or ToolContext(mission_id=mission_id)
        return adapter.run(target, parameters, run_context)

    def execute_workflow_action(
        self, action: str, target: str, parameters: dict[str, Any]
    ) -> Result[ToolOutput, Exception]:
        """Executor-port adapter for the workflow engine."""
        output = self.execute(action, target, parameters)
        if output.ok:
            return Success(output)
        return Failure(ToolExecutionError(f"Tool '{action}' failed: {output.error}"))
