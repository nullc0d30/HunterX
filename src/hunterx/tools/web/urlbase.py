# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for URL-discovery / crawler tools.

Every URL discovery tool (gospider, hakrawler, gau, waybackurls, urlfinder)
invokes an external binary through the shared runner seam and normalizes its
output (JSONL or plain URL lines) into canonical :class:`URLObservation`
instances emitted under the pipeline ``crawl`` payload.

Hostile output is treated as data: malformed lines are skipped, never executed.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.web.models import URLObservation, _http_method
from hunterx.domain.web.urls import URLNormalizer
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.web.base import WebToolAdapter


class UrlDiscoveryAdapter(WebToolAdapter, abc.ABC):
    """Shared base for external URL-discovery adapters.

    Subclasses declare a ``descriptor`` and implement :meth:`build_argv` and
    :meth:`parse_lines`. The default :meth:`run` invokes the binary, captures
    output and emits canonical URL observations.
    """

    descriptor: ToolDescriptor

    #: Source label stamped on every observation.
    source: str = "url"

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        self._runner = runner or BinaryRunner()
        self._normalizer = URLNormalizer()

    @property
    def runner(self) -> BinaryRunner:
        """Return the binary runner used by this adapter."""
        return self._runner

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_lines(self, context: ExecutionContext, lines: list[str]) -> list[str]:
        """Convert raw output lines into canonical URL strings."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, parse URLs and emit canonical observations."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        urls = self.parse_lines(context, _safe_lines(result.stdout))
        observations = self._observations(context, urls)
        self.emit(collector, urls=observations)

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project URL observations into the legacy asset surface."""
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

    # -- helpers -------------------------------------------------------------

    def _observations(self, context: ExecutionContext, urls: list[str]) -> list[URLObservation]:
        observations: list[URLObservation] = []
        seen: set[str] = set()
        for url in urls:
            url = (url or "").strip()
            if not url:
                continue
            try:
                parsed = self._normalizer.parse(url)
            except ValueError:
                continue
            key = parsed.url
            if key in seen:
                continue
            seen.add(key)
            observations.append(
                URLObservation(
                    url=parsed.url,
                    method=_http_method("GET"),
                    origin=parsed.origin,
                    path=parsed.path,
                    query=parsed.query,
                    status_code=None,
                    content_type=None,
                    source=self.source,
                    tool_id=context.tool_id,
                    target_key=self._target_key(context, url),
                    correlation_id=context.correlation_id,
                    mission_id=context.mission_id,
                    execution_id=context.execution_id,
                )
            )
        return observations

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)

    def _param_int(self, context: ExecutionContext, name: str, default: int) -> int:
        try:
            return int(self._param(context, name, default))
        except (TypeError, ValueError):
            return default

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")


def _safe_lines(stdout: str) -> list[str]:
    """Return bounded, non-empty output lines (defensive against hostile output)."""
    return [(line or "").strip() for line in (stdout or "").splitlines() if (line or "").strip()]


__all__ = ["UrlDiscoveryAdapter"]
