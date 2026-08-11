# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for API intelligence tools.

Every API intelligence adapter implements the SDK :class:`ToolAdapter`
lifecycle and shares this base. Adapters serialize canonical API observations
into the pipeline's JSON payload under the ``apis`` key, each entry carrying a
``type`` discriminator so :func:`~hunterx.domain.api.models.observations_from_payload`
can rebuild typed records. The base provides provenance helpers so adapters
stay focused on their tool-specific discovery logic.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.api.models import (
    FINDINGS_KEY,
    ApiAuthObservation,
    ApiFilterObservation,
    APIHostObservation,
    ApiOperationObservation,
    ApiPaginationObservation,
    ApiRateLimitObservation,
    APISpecObservation,
)
from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class ApiToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK API intelligence adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`run`. The
    base provides payload serialization, parameter access and provenance
    helpers so adapters stay focused on their tool-specific discovery.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    # -- payload helpers -----------------------------------------------------

    def emit(
        self,
        collector: OutputCollector,
        *,
        hosts: list[APIHostObservation] | None = None,
        specs: list[APISpecObservation] | None = None,
        operations: list[ApiOperationObservation] | None = None,
        auth: list[ApiAuthObservation] | None = None,
        rate_limits: list[ApiRateLimitObservation] | None = None,
        paginations: list[ApiPaginationObservation] | None = None,
        filters: list[ApiFilterObservation] | None = None,
    ) -> None:
        """Write canonical API observations onto ``collector`` as a JSON payload."""
        entries: list[dict[str, Any]] = []
        for item in hosts or ():
            entries.append(item.to_dict())
        for item in specs or ():
            entries.append(item.to_dict())
        for item in operations or ():
            entries.append(item.to_dict())
        for item in auth or ():
            entries.append(item.to_dict())
        for item in rate_limits or ():
            entries.append(item.to_dict())
        for item in paginations or ():
            entries.append(item.to_dict())
        for item in filters or ():
            entries.append(item.to_dict())
        collector.set_json({FINDINGS_KEY: entries, "count": len(entries)})

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project API observations into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get(FINDINGS_KEY), list):
            entries = [entry for entry in payload[FINDINGS_KEY] if isinstance(entry, dict)]
            tool_output.assets = [entry for entry in entries if entry.get("type") == "api-host"]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- parameter helpers ---------------------------------------------------

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        """Return a parameter value from the execution context."""
        return context.parameters.get(name, default)

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        try:
            return int(self._param(context, name, default))
        except (TypeError, ValueError):
            return default

    def _records(self, context: ExecutionContext, name: str) -> list[dict[str, Any]]:
        """Return a parameter value normalized to a list of dictionaries."""
        value = self._param(context, name)
        if value is None:
            return []
        if isinstance(value, dict):
            return [dict(value)]
        if isinstance(value, (list, tuple)):
            items: list[dict[str, Any]] = []
            for item in value:
                if isinstance(item, dict):
                    items.append(dict(item))
                elif isinstance(item, str):
                    items.append({"url": item})
            return items
        return [{"url": str(value)}]

    def _mode(self, context: ExecutionContext) -> str:
        """Return the execution posture from parameters (default ``hybrid``)."""
        mode = str(self._param(context, "mode", "hybrid") or "hybrid").lower()
        return mode if mode in ("passive", "active", "hybrid") else "hybrid"

    def _is_passive(self, context: ExecutionContext) -> bool:
        """Return whether the run must avoid generating network traffic."""
        return self._mode(context) == "passive"
