# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""GraphQL testing tool adapters.

Integrates ``graphqlmap`` and ``inql`` — the GraphQL introspection and testing
tools — into the Tool Integration SDK. External binaries run through the shared
runner seam and emit canonical API observations under the pipeline ``apis``
payload with a ``type`` discriminator.

Introspection results are observations; they never constitute a finding on
their own.
"""

from __future__ import annotations

import abc
import re
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class GraphQLBinaryAdapter(ToolAdapter, abc.ABC):
    """Shared base for external GraphQL testing adapters."""

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
        """Convert the captured tool output into canonical API observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit API observations."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        records = self.parse_output(context, result)
        collector.set_json({"apis": records, "count": len(records)})

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
        if isinstance(payload, dict) and isinstance(payload.get("apis"), list):
            tool_output.assets = [entry for entry in payload["apis"] if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        return context.parameters.get(name, default)

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")


class GraphQLmapAdapter(GraphQLBinaryAdapter):
    """SDK adapter for ``graphqlmap`` — GraphQL attack surface testing."""

    descriptor = ToolDescriptor(
        name="graphqlmap",
        version="0.1.0",
        description="GraphQL attack surface and introspection testing tool.",
        entrypoint="hunterx.tools.api.graphql_binaries:GraphQLmapAdapter",
        targets=("url",),
        capabilities=("graphql-testing", "graphql-introspection", "graphql-analysis"),
        permissions=("network",),
        parameters={
            "headers": {"type": "object", "description": "HTTP headers to send."},
            "method": {"type": "string", "description": "HTTP method (GET/POST)."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["graphqlmap", "-u", context.target, "-v"]
        method = str(context.parameters.get("method") or "POST").upper()
        if method == "GET":
            argv += ["--method", "GET"]
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        records: list[dict[str, Any]] = []
        text = result.stdout
        if re.search(r"introspection|schema|graphql", text, re.IGNORECASE):
            records.append(
                {
                    "type": "graphql-introspection",
                    "endpoint": str(context.target),
                    "detail": "GraphQL introspection endpoint detected",
                    "evidence": text[:1024],
                    "tool_id": "graphqlmap",
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        return records


class InQLAdapter(GraphQLBinaryAdapter):
    """SDK adapter for ``inql`` — GraphQL introspection schema generation."""

    descriptor = ToolDescriptor(
        name="inql",
        version="5.3.2",
        description="Generate introspection schemas and queries for GraphQL endpoints.",
        entrypoint="hunterx.tools.api.graphql_binaries:InQLAdapter",
        targets=("url",),
        capabilities=("graphql-introspection", "graphql-analysis"),
        permissions=("network",),
        parameters={
            "output": {"type": "string", "description": "Directory where the schema is written (artifact)."},
            "generate_queries": {"type": "boolean", "description": "Generate queries for every type."},
        },
    )

    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Build argv."""
        argv = ["inql", str(context.target)]
        output = context.parameters.get("output")
        if isinstance(output, str) and output:
            argv += ["-o", output]
        if self._param_bool(context, "generate_queries", False):
            argv.append("--generate-query")
        return argv

    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[dict[str, Any]]:
        """Parse output."""
        text = result.stdout
        schemas = _schema_paths(text)
        records: list[dict[str, Any]] = []
        if schemas:
            records.append(
                {
                    "type": "graphql-introspection",
                    "endpoint": str(context.target),
                    "detail": "GraphQL introspection schema generated",
                    "schemas": schemas,
                    "tool_id": "inql",
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        elif re.search(r"success|saved|wrote", text, re.IGNORECASE):
            records.append(
                {
                    "type": "graphql-introspection",
                    "endpoint": str(context.target),
                    "detail": "GraphQL introspection completed",
                    "schemas": [],
                    "tool_id": "inql",
                    "correlation_id": context.correlation_id,
                    "mission_id": context.mission_id,
                    "execution_id": context.execution_id,
                }
            )
        return records


_SCHEMA_RE = re.compile(r"([^\s]+/schema\.graphql|schemas?/[^\s]+\.graphql)", re.IGNORECASE)


def _schema_paths(text: str) -> list[str]:
    paths: list[str] = []
    for match in _SCHEMA_RE.finditer(text):
        path = match.group(1).strip().strip("'\"")
        if path not in paths:
            paths.append(path)
    return paths


__all__ = ["GraphQLmapAdapter", "InQLAdapter"]
