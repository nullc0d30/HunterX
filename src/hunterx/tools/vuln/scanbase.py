# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for binary vulnerability scanners.

Every external vulnerability scanner (Nuclei, Trivy, and future scanners)
implements the SDK :class:`ToolAdapter` lifecycle and shares this base. Scanners
are invoked through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam and emit canonical
*candidate* records into the pipeline JSON payload under the ``candidates`` key.

A scanner output is an OBSERVATION / CANDIDATE — never a validated finding. Every
candidate record carries ``requires_validation = True`` and a bounded confidence
contribution so the Proof and Validation subsystems retain authority over the
final verdict.
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


class VulnerabilityScanAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK binary vulnerability scanner adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`build_argv`
    and :meth:`parse_output`. The default :meth:`run` performs the external
    invocation, records exit/stdout/stderr on the collector and writes the
    parsed candidate records as JSON.
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
        """No setup required for scanners; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    # -- adapter contract ----------------------------------------------------

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_output(
        self, context: ExecutionContext, result: CommandResult
    ) -> list[dict[str, Any]]:
        """Convert the captured tool output into canonical candidate records."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit candidate records."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json(self._payload(records))

    def validate_output(
        self, context: ExecutionContext, output: ExecutionOutput
    ) -> tuple[bool, list[str]]:
        """Validate collected output; empty candidate sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project candidate records into the legacy asset surface.

        Candidates are assets for downstream correlation; they are never
        findings on their own.
        """
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("candidates"), list):
            tool_output.assets = [
                entry for entry in payload["candidates"] if isinstance(entry, dict)
            ]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _payload(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Build the JSON payload attached to the execution output."""
        return {
            "candidates": records,
            "count": len(records),
        }

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        """Return a parameter value from the execution context."""
        return context.parameters.get(name, default)

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")

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
