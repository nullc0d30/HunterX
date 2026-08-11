# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for secret discovery tools.

Every secret discovery tool adapter (gitleaks, and future secret scanners)
implements the SDK :class:`ToolAdapter` lifecycle and shares this base.
External binaries are invoked through the shared
:class:`~hunterx.tools.recon.runner.BinaryRunner` seam and emit canonical
redacted secret records into the pipeline JSON payload under the ``secrets``
key.

SECURITY BOUNDARY: detected secrets are extremely sensitive. This base never
persists raw values — it stores ``secret_type``, ``location``, a SHA-256
``fingerprint``, a ``masked_value``, ``source``, ``confidence`` and
``provenance`` only. Raw matches are dropped at parse time.
"""

from __future__ import annotations

import abc
import hashlib
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.shared.masking import mask_value
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class SecretToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK secret discovery adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`build_argv`
    and :meth:`parse_output`. The default :meth:`run` performs the external
    invocation, records exit/stdout/stderr on the collector and writes the
    parsed (redacted) secret records as JSON.
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
        """No setup required for secret tools; hook kept for parity."""

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
        """Convert the captured tool output into canonical redacted records."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit redacted secret records."""
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
        """Validate collected output; empty secret sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project secret records into the legacy asset surface (redacted only)."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get("secrets"), dict):
            records = payload["secrets"].get("findings") or []
            tool_output.assets = [entry for entry in records if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _payload(records: list[dict[str, Any]]) -> dict[str, Any]:
        """Build the JSON payload attached to the execution output."""
        return {
            "secrets": {"findings": records},
            "count": len(records),
        }

    @staticmethod
    def _fingerprint(secret: str, location: str, rule: str) -> str:
        """Return a deterministic SHA-256 fingerprint for a secret finding.

        The fingerprint identifies the secret without exposing its value.
        """
        material = f"{rule}\x00{location}\x00{secret}".encode("utf-8", errors="replace")
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def _masked(secret: str, *, reveal_head: int = 4, reveal_tail: int = 0) -> str:
        """Return a masked preview of ``secret`` (never the raw value)."""
        return mask_value(secret, reveal_head=reveal_head, reveal_tail=reveal_tail)

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        """Return a parameter value from the execution context."""
        return context.parameters.get(name, default)

    def _param_bool(self, context: ExecutionContext, name: str, default: bool) -> bool:
        value = self._param(context, name, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes")
