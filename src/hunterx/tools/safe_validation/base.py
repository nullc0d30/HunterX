# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for safe validation tools.

Every safe validation tool integrates with HunterX through the Tool Integration
SDK :class:`ToolAdapter` lifecycle. This base class defines the safe-probe
contract: adapters receive a bounded, already-gated probe request through the
execution parameters and serialize canonical observations into the pipeline JSON
payload under the ``observations`` key.

No validation adapter may bypass the SDK, and no adapter may perform destructive,
weaponized or out-of-scope actions — the parameters it receives have already
passed the scope and safety gates of the validation engine.
"""

from __future__ import annotations

import abc
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.tools import ToolDescriptor
from hunterx.domain.vulnerability_validation.enums import EvidenceKind
from hunterx.domain.vulnerability_validation.models import ValidationObservation
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector

#: Canonical observation payload key emitted by safe validation adapters.
OBSERVATIONS_KEY = "observations"


class ValidationToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for in-process safe validation adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`probe`, which
    executes one bounded safe check and returns canonical observations.
    """

    descriptor: ToolDescriptor

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for in-process probes; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    @abc.abstractmethod
    def probe(
        self,
        context: ExecutionContext,
        *,
        target: str,
        parameters: dict[str, Any],
    ) -> list[ValidationObservation]:
        """Execute one bounded safe probe and return canonical observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Run the probe and emit canonical observations as JSON."""
        params = dict(context.parameters or {})
        target = str(params.pop("target", context.target) or context.target)
        observations = self.probe(context, target=target, parameters=params)
        collector.set_exit_code(0)
        collector.set_json(
            {
                OBSERVATIONS_KEY: [observation.to_dict() for observation in observations],
                "count": len(observations),
                "tool_id": context.tool_id,
                "correlation_id": context.correlation_id,
            }
        )

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project normalized observations into the canonical tool output."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        payload = output.json
        if isinstance(payload, dict) and isinstance(payload.get(OBSERVATIONS_KEY), list):
            tool_output.assets = [entry for entry in payload[OBSERVATIONS_KEY] if isinstance(entry, dict)]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output


def _observation(
    kind: EvidenceKind,
    value: str,
    *,
    confidence: float = 1.0,
    source: str = "",
    metadata: dict[str, Any] | None = None,
) -> ValidationObservation:
    return ValidationObservation(
        kind=kind,
        value=value,
        source=source,
        confidence=max(0.0, min(1.0, confidence)),
        metadata=dict(metadata or {}),
    )


__all__ = ["OBSERVATIONS_KEY", "ValidationToolAdapter", "_observation"]
