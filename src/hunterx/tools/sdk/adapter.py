# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool adapter framework.

The contract every SDK-integrated tool implements. An adapter declares a
:class:`ToolDescriptor` and implements the execution lifecycle hooks the
pipeline drives: prepare → run → validate output → normalize → cleanup.
Legacy :class:`BaseTool` adapters are bridged so existing tools keep working
unchanged.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import BaseTool, ToolOutput
from hunterx.tools.sdk.output import OutputCollector


class ToolAdapter(abc.ABC):
    """Full-lifecycle contract for SDK-integrated tools.

    Subclasses declare ``descriptor`` and implement :meth:`run`. The remaining
    hooks are optional and default to no-ops.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    def prepare(self, context: ExecutionContext) -> None:  # noqa: B027 - optional hook
        """Perform setup before execution (create dirs, resolve inputs)."""

    @abc.abstractmethod
    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Execute the tool and write its output into ``collector``.

        The adapter is responsible for the real work (invoking a binary,
        querying a service, reading files). It should write text via
        ``collector.attach_stdout``, structured data via ``collector.set_json``
        and reference artifacts via ``collector.attach_file``.
        """

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; return ``(ok, errors)``.

        The default considers non-zero exit codes and empty output as invalid.
        """
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Convert collected output into canonical :class:`ToolOutput`.

        The default projects JSON ``findings`` records and stdout evidence.
        """
        return _default_normalize(output)

    def cleanup(self, context: ExecutionContext) -> None:  # noqa: B027 - optional hook
        """Release resources after execution completes or fails."""


class LegacyToolBridge(ToolAdapter):
    """Adapt an existing :class:`BaseTool` to the SDK adapter contract.

    Allows legacy tool adapters to participate in the new execution pipeline
    without modification. ``run`` delegates to ``BaseTool.run`` with a
    :class:`~hunterx.tools.adapter.ToolContext` derived from the execution.
    """

    def __init__(self, tool: BaseTool) -> None:
        self._tool = tool
        self.descriptor = tool.descriptor

    @property
    def tool(self) -> BaseTool:
        """Return the wrapped legacy tool instance."""
        return self._tool

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Run the wrapped legacy tool and project its output into ``collector``."""
        from hunterx.tools.adapter import ToolContext

        legacy_context = ToolContext(
            mission_id=context.mission_id,
            secrets_resolver=None,
        )
        output = self._tool.run(context.target, context.parameters, legacy_context)
        collector.set_exit_code(0 if output.ok else 1)
        if output.error:
            collector.attach_stderr(output.error)
        if output.raw is not None:
            if isinstance(output.raw, str):
                collector.attach_stdout(output.raw)
            elif isinstance(output.raw, dict):
                collector.set_json(output.raw)
        for finding in output.findings:
            collector.attach_stdout(f"{finding.severity}: {finding.title} ({finding.target})\n")


class AdapterFactory:
    """Instantiate tool adapters from descriptors or entry points."""

    def __init__(self, *, discovery: Any = None) -> None:
        self._discovery = discovery

    def create(self, entrypoint: str) -> ToolAdapter:
        """Create an adapter from a ``module.path:ClassName`` entry point.

        SDK adapters (subclasses of :class:`ToolAdapter`) are instantiated
        directly; legacy :class:`BaseTool` adapters are resolved through the
        legacy discovery service and bridged.
        """
        import importlib

        module_path, class_name = entrypoint.split(":", 1)
        try:
            module = importlib.import_module(module_path)
            candidate = getattr(module, class_name)
        except (ImportError, AttributeError) as error:
            raise TypeError(f"could not load adapter entrypoint '{entrypoint}': {error}") from error
        if isinstance(candidate, type) and issubclass(candidate, ToolAdapter):
            return candidate()
        from hunterx.tools.discovery import ToolDiscovery

        discovery = self._discovery or ToolDiscovery()
        instance = discovery.instantiate(entrypoint)
        if isinstance(instance, BaseTool):
            return LegacyToolBridge(instance)
        raise TypeError(f"'{entrypoint}' does not produce a tool adapter instance.")

    def bridge(self, tool: BaseTool) -> LegacyToolBridge:
        """Wrap a legacy :class:`BaseTool` instance as an SDK adapter."""
        return LegacyToolBridge(tool)


def _default_normalize(output: ExecutionOutput) -> ToolOutput:
    """Project an :class:`ExecutionOutput` into a canonical :class:`ToolOutput`."""
    from hunterx.tools.adapter import ToolOutput

    normalized = ToolOutput()
    if output.stdout:
        normalized.raw = output.stdout
    if output.json and isinstance(output.json, dict):
        records = output.json.get("findings", [])
        if isinstance(records, list):
            for record in records:
                if isinstance(record, dict):
                    from hunterx.plugins.sdk.results import FindingResult

                    normalized.findings.append(
                        FindingResult(
                            title=str(record.get("title", "")),
                            severity=str(record.get("severity", "medium")).lower(),
                            target=str(record.get("target", "")),
                            description=str(record.get("description", "")),
                            risk_score=_optional_float(record.get("risk_score")),
                            metadata=record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {},
                        )
                    )
    if output.stderr:
        normalized.error = output.stderr
    return normalized


def _optional_float(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    return None
