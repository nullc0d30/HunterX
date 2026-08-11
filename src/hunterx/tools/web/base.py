# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for web crawling tools.

Every web crawling tool adapter implements the SDK :class:`ToolAdapter`
lifecycle and shares this base. External binaries (Katana) are invoked through
the shared :class:`~hunterx.tools.recon.runner.BinaryRunner` seam; in-process
tools run directly. All adapters serialize canonical crawl observations into
the pipeline's JSON payload under the ``crawl`` key.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.web.models import (
    APIEndpoint,
    AuthenticationBoundary,
    CrawlEvidence,
    GraphQLEndpoint,
    Redirect,
    URLObservation,
    WebSocketEndpoint,
)
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class WebToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK web crawling adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`run`. The
    base provides payload serialization, parameter access and provenance
    helpers so adapters stay focused on their tool-specific parsing.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    # -- payload helpers -----------------------------------------------------

    def emit(
        self,
        collector: OutputCollector,
        *,
        urls: list[URLObservation] | None = None,
        redirects: list[Redirect] | None = None,
        endpoints: list[APIEndpoint] | None = None,
        websockets: list[WebSocketEndpoint] | None = None,
        graphqls: list[GraphQLEndpoint] | None = None,
        auth_boundaries: list[AuthenticationBoundary] | None = None,
        evidence: list[CrawlEvidence] | None = None,
    ) -> None:
        """Write crawl observations onto ``collector`` as a JSON payload."""
        container: dict[str, Any] = {}
        if urls:
            container["urls"] = [observation.to_dict() for observation in urls]
        if redirects:
            container["redirects"] = [item.to_dict() for item in redirects]
        if endpoints:
            container["endpoints"] = [item.to_dict() for item in endpoints]
        if websockets:
            container["websockets"] = [item.to_dict() for item in websockets]
        if graphqls:
            container["graphqls"] = [item.to_dict() for item in graphqls]
        if auth_boundaries:
            container["auth_boundaries"] = [item.to_dict() for item in auth_boundaries]
        if evidence:
            container["evidence"] = [item.to_dict() for item in evidence]
        collector.set_json({"crawl": container, "count": len(urls or [])})

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project crawl observations into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("crawl"), dict):
            urls = payload["crawl"].get("urls") or []
            tool_output.assets = [entry for entry in urls if isinstance(entry, dict)]
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

    def _target_id(self, context: ExecutionContext) -> str | None:
        """Return the owning target id from the execution parameters."""
        target_id = self._param(context, "target_id")
        return target_id if isinstance(target_id, str) and target_id else None

    def _target_key(self, context: ExecutionContext, url: str) -> str:
        """Return the canonical owning host key for a crawled URL."""
        from hunterx.domain.web.urls import URLNormalizer

        try:
            return URLNormalizer().host(url)
        except ValueError:
            return context.target.strip()
