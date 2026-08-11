# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for topology (route-mapping) tools.

Shares the Tool Integration SDK lifecycle with the recon/livehost adapters:
invoke the external binary through an injectable runner, parse the captured
output into canonical :class:`RouteRecord` instances and serialize them into the
pipeline payload under ``routes``. Adapters stay binary-free in unit tests by
injecting a fake runner.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.topology.models import RouteRecord, routes_to_payload


class TopologyToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK topology adapters.

    Subclasses declare a ``descriptor`` and implement :meth:`build_argv` and
    :meth:`parse_output` (returning :class:`RouteRecord` instances).
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        self._runner = runner or BinaryRunner()

    @property
    def runner(self) -> BinaryRunner:
        """Return the binary runner used by this adapter."""
        return self._runner

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for topology tools."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[RouteRecord]:
        """Convert the captured tool output into canonical route records."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit route records."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json(routes_to_payload(records))

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty route sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project route records into a canonical :class:`ToolOutput`."""
        from hunterx.tools.topology.models import routes_from_payload

        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        for record in routes_from_payload(output.json):
            tool_output.assets.append(record.to_dict())
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers ------------------------------------------------------------

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        value = self._param(context, name, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _param_float(self, context: ExecutionContext, name: str, default: float) -> float:
        value = self._param(context, name, default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
