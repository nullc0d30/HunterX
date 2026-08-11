# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for DNS intelligence tools.

Every DNS tool adapter implements the SDK :class:`ToolAdapter` lifecycle and
shares this base: it invokes the external binary through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam, parses the captured
output into canonical :class:`DnsRecord` instances and serialises them into the
pipeline's JSON payload under ``dns_records``. Adapters stay binary-free in
unit tests: tests inject a fake runner and assert on the JSON payload.

The runner is imported from ``hunterx.tools.recon.runner`` — the single guarded
subprocess seam — so DNS adapters never touch ``subprocess`` directly.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from typing import Any

from hunterx.domain.dns.models import DnsRecord
from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class DnsToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK DNS adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`build_argv`
    and :meth:`parse_output`. The default :meth:`run` performs the external
    invocation, records exit/stdout/stderr on the collector and writes the
    parsed records as JSON.
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
        """No setup required for DNS tools; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    # -- adapter contract ----------------------------------------------------

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[DnsRecord]:
        """Convert the captured tool output into canonical DNS records."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit DNS records."""
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

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty record sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project DNS records into the legacy asset surface."""
        from hunterx.domain.dns.models import records_from_payload

        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        records = records_from_payload(output.json)
        tool_output.assets = [record.to_dict() for record in records]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _payload(records: Sequence[DnsRecord]) -> dict[str, Any]:
        """Build the JSON payload attached to the execution output."""
        return {
            "dns_records": [record.to_dict() for record in records],
            "count": len(records),
        }

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        """Return a parameter value from the execution context."""
        return context.parameters.get(name, default)

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        value = self._param(context, name, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _target_id(self, context: ExecutionContext) -> str | None:
        """Return the owning target id from the execution parameters."""
        target_id = context.parameters.get("target_id")
        return target_id if isinstance(target_id, str) and target_id else None
