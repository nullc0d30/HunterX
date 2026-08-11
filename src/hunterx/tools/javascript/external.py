# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""External JavaScript endpoint/secret extraction adapters.

Integrates ``linkfinder``, ``secretfinder`` and ``xnlinkfinder`` — the
JavaScript link/secret extraction tools — into the Tool Integration SDK. Each
adapter invokes its external binary through the shared runner seam and
normalizes CLI output into canonical endpoint/secret observations.

Extracted strings are data: they are never executed, and secrets are projected
as redacted candidate records for later validation.
"""

from __future__ import annotations

import abc
import json
import re
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector

_ENDPOINT_RE = re.compile(r"(?:^|\s|['\"`])+(https?://[^\s'\"`<>]+|/[A-Za-z0-9_\-\./]+\.[a-z]{2,}(?:\?[^\s'\"`<>]*)?)", re.IGNORECASE)


class ExternalJsToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for external JavaScript extraction adapters."""

    descriptor: ToolDescriptor

    def __init__(self, runner: BinaryRunner | None = None) -> None:
        self._runner = runner or BinaryRunner()

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
    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Convert the captured tool output into canonical observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit observations."""
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
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project JS extraction records into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("observations"), list):
            tool_output.assets = [entry for entry in payload["observations"] if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _payload(records: list[dict[str, Any]]) -> dict[str, Any]:
        return {"observations": records, "count": len(records)}

    def _endpoint_record(self, value: str, context: ExecutionContext, *, kind: str = "endpoint") -> dict[str, Any]:
        return {
            "kind": kind,
            "value": value,
            "tool_id": context.tool_id,
            "source": context.tool_id,
            "correlation_id": context.correlation_id,
            "mission_id": context.mission_id,
            "execution_id": context.execution_id,
        }

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")


class LinkFinderAdapter(ExternalJsToolAdapter):
    """SDK adapter for ``linkfinder`` JavaScript endpoint extraction."""

    descriptor = ToolDescriptor(
        name="linkfinder",
        version="1.0.5",
        description="Extract endpoints from JavaScript files in a web application.",
        entrypoint="hunterx.tools.javascript.external:LinkFinderAdapter",
        targets=("url",),
        capabilities=("endpoint-extraction", "javascript-discovery"),
        permissions=("network",),
        parameters={
            "script": {"type": "string", "description": "Local JS file to analyze (instead of a URL)."},
            "dump": {"type": "boolean", "description": "Dump all matches to output."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        script = context.parameters.get("script")
        if isinstance(script, str) and script:
            argv = ["linkfinder", "-i", script, "-o", "cli"]
        else:
            argv = ["linkfinder", "-i", context.target, "-o", "cli"]
        if self._param_bool(context, "dump", False):
            argv.append("-d")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            value = line.strip()
            if not value:
                continue
            for candidate in _endpoints_in(line):
                if candidate in seen:
                    continue
                seen.add(candidate)
                records.append(self._endpoint_record(candidate, context, kind="endpoint"))
        return records


class SecretFinderAdapter(ExternalJsToolAdapter):
    """SDK adapter for ``secretfinder`` JavaScript secret extraction."""

    descriptor = ToolDescriptor(
        name="secretfinder",
        version="1.0.0",
        description="Find sensitive data (API keys, tokens) inside JavaScript files.",
        entrypoint="hunterx.tools.javascript.external:SecretFinderAdapter",
        targets=("url",),
        capabilities=("secret-discovery", "token-discovery"),
        permissions=("network",),
        parameters={
            "script": {"type": "string", "description": "Local JS file to analyze (instead of a URL)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        script = context.parameters.get("script")
        input_value = script if isinstance(script, str) and script else context.target
        return ["secretfinder", "-i", input_value, "-o", "cli"]

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        try:
            payload = json.loads(result.stdout or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            for url, secrets in payload.items():
                if not isinstance(url, str):
                    continue
                if isinstance(secrets, dict):
                    for secret_type, values in secrets.items():
                        for value in _string_list(values):
                            records.append(
                                {
                                    "kind": "secret",
                                    "secret_type": str(secret_type),
                                    "value": _mask(value),
                                    "location": url,
                                    "tool_id": context.tool_id,
                                    "source": "secretfinder",
                                    "correlation_id": context.correlation_id,
                                    "mission_id": context.mission_id,
                                    "execution_id": context.execution_id,
                                }
                            )
        return records


class XnLinkFinderAdapter(ExternalJsToolAdapter):
    """SDK adapter for ``xnlinkfinder`` JavaScript endpoint extraction."""

    descriptor = ToolDescriptor(
        name="xnlinkfinder",
        version="1.0.0",
        description="Extract endpoints from JavaScript files across multiple sources.",
        entrypoint="hunterx.tools.javascript.external:XnLinkFinderAdapter",
        targets=("url",),
        capabilities=("endpoint-extraction", "javascript-discovery"),
        permissions=("network",),
        parameters={
            "in_scope": {"type": "boolean", "description": "Only output in-scope endpoints."},
            "secrets": {"type": "boolean", "description": "Extract secret-like strings too."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["xnLinkFinder", "-i", context.target, "-o", "cli"]
        if self._param_bool(context, "in_scope", True):
            argv.append("-sp")
        if self._param_bool(context, "secrets", False):
            argv.append("-sf")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for line in result.stdout.splitlines():
            value = line.strip()
            if not value or value.startswith("["):
                continue
            for candidate in _endpoints_in(line):
                if candidate in seen:
                    continue
                seen.add(candidate)
                records.append(self._endpoint_record(candidate, context, kind="endpoint"))
        return records


def _endpoints_in(line: str) -> list[str]:
    matches = _ENDPOINT_RE.findall(line)
    values: list[str] = []
    for match in matches:
        value = match.strip().rstrip(".,;\"'`")
        if value.startswith("/"):
            value = _absolutize(value)
        if value and value not in values:
            values.append(value)
    return values


def _absolutize(path: str) -> str:
    # Keep relative paths intact; they are resolved against the target later.
    return path


def _string_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]}"


__all__ = ["LinkFinderAdapter", "SecretFinderAdapter", "XnLinkFinderAdapter"]
