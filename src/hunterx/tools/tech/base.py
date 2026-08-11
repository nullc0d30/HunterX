# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Base adapter for technology fingerprinting tools.

Every fingerprinting tool adapter implements the SDK :class:`ToolAdapter`
lifecycle and shares this base: it invokes the external binary through the
shared :class:`~hunterx.tools.recon.runner.BinaryRunner` seam, parses the
captured output into canonical :class:`TechnologyObservation` records and
serialises them into the pipeline's JSON payload under the ``technologies`` key
with a ``type`` discriminator. Adapters stay binary-free in unit tests: tests
inject a fake runner and assert on the JSON payload.

The runner is imported from ``hunterx.tools.recon.runner`` — the single guarded
subprocess seam — so fingerprinting adapters never touch ``subprocess``
directly.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence
from typing import Any

from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.domain.technology.models import (
    TechnologyObservation,
    infer_asset_type,
    make_observation,
    observations_from_payload,
)
from hunterx.domain.technology.resolver import TechnologyResolver
from hunterx.domain.technology.version import VersionResolver
from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.adapter import ToolOutput
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.adapter import ToolAdapter
from hunterx.tools.sdk.output import OutputCollector


class TechToolAdapter(ToolAdapter, abc.ABC):
    """Shared base for SDK technology fingerprinting adapters.

    Subclasses must declare a ``descriptor`` and implement :meth:`build_argv`
    and :meth:`parse_output`. The default :meth:`run` performs the external
    invocation, records exit/stdout/stderr on the collector and writes the
    parsed technology observations as JSON.
    """

    #: Static descriptor; subclasses must set this.
    descriptor: ToolDescriptor

    def __init__(
        self,
        runner: BinaryRunner | None = None,
        resolver: TechnologyResolver | None = None,
    ) -> None:
        self._runner = runner or BinaryRunner()
        self._resolver = resolver or TechnologyResolver()
        self._versions = VersionResolver()

    @property
    def runner(self) -> BinaryRunner:
        """Return the binary runner used by this adapter."""
        return self._runner

    @property
    def resolver(self) -> TechnologyResolver:
        """Return the technology resolver used by this adapter."""
        return self._resolver

    def prepare(self, context: ExecutionContext) -> None:
        """No setup required for fingerprinting tools; hook kept for parity."""

    def cleanup(self, context: ExecutionContext) -> None:
        """Nothing to release; hook kept for parity."""

    # -- adapter contract ----------------------------------------------------

    @abc.abstractmethod
    def build_argv(self, context: ExecutionContext) -> list[str]:
        """Return the full command line for ``context``."""

    @abc.abstractmethod
    def parse_output(self, context: ExecutionContext, result: CommandResult) -> list[TechnologyObservation]:
        """Convert the captured tool output into canonical technology observations."""

    def run(self, context: ExecutionContext, collector: OutputCollector) -> None:
        """Invoke the binary, capture output and emit technology observations."""
        argv = self.build_argv(context)
        timeout = context.timeout_effective or 0.0
        result = self._runner.run(argv, timeout_s=timeout, tool_id=context.tool_id)
        collector.set_exit_code(result.returncode)
        if result.stdout:
            collector.attach_stdout(result.stdout)
        if result.stderr:
            collector.attach_stderr(result.stderr)
        observations = self.parse_output(context, result)
        collector.set_json(self._payload(observations))

    def validate_output(self, context: ExecutionContext, output: ExecutionOutput) -> tuple[bool, list[str]]:
        """Validate collected output; empty observation sets are valid results."""
        errors: list[str] = []
        if output.exit_code != 0:
            errors.append(f"exit code {output.exit_code}")
        if not output.has_content:
            errors.append("no output produced")
        return (not errors, errors)

    def normalize(self, context: ExecutionContext, output: ExecutionOutput) -> ToolOutput:
        """Project technology observations into the legacy asset surface."""
        tool_output = ToolOutput()
        if output.stdout:
            tool_output.raw = output.stdout
        observations = observations_from_payload(output.json)
        tool_output.assets = [observation.to_dict() for observation in observations]
        if output.stderr:
            tool_output.error = output.stderr
        return tool_output

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _payload(observations: Sequence[TechnologyObservation]) -> dict[str, Any]:
        """Build the JSON payload attached to the execution output."""
        return {
            "technologies": [observation.to_dict() for observation in observations],
            "count": len(observations),
        }

    def _param(self, context: ExecutionContext, name: str, default: Any = None) -> Any:
        """Return a parameter value from the execution context."""
        return context.parameters.get(name, default)

    def _target_id(self, context: ExecutionContext) -> str | None:
        """Return the owning target id from the execution parameters."""
        target_id = context.parameters.get("target_id")
        return target_id if isinstance(target_id, str) and target_id else None

    def _asset(self, context: ExecutionContext) -> tuple[str, str]:
        """Return ``(asset, asset_type)`` for an execution's target."""
        target = context.target.strip()
        asset_type = self._param(context, "asset_type")
        if not isinstance(asset_type, str) or not asset_type:
            asset_type = infer_asset_type(target)
        return target, asset_type

    def _observation(
        self,
        context: ExecutionContext,
        raw_name: str,
        *,
        canonical_hint: str = "",
        version: str = "",
        version_strong: bool = False,
        source: str = "",
        category: str = "",
        asset: str | None = None,
        asset_type: str | None = None,
        evidence: tuple[dict[str, Any], ...] = (),
        confidence: float = 1.0,
    ) -> TechnologyObservation:
        """Build a canonical observation for one detected technology."""
        resolution = self._resolver.resolve(raw_name, canonical_hint=canonical_hint)
        version_spec = None
        resolved_version = version or resolution.base_version
        if resolved_version:
            version_spec = self._versions.extract(resolved_version).to_spec()
            if version_strong:
                version_spec = self._versions.extract(resolved_version).to_spec()
                from dataclasses import replace

                version_spec = replace(version_spec, confidence=self._versions.classify(version_spec.value, strong=True))
        effective_asset, effective_type = self._asset(context)
        return make_observation(
            asset=asset or effective_asset,
            asset_type=asset_type or effective_type,
            raw_name=raw_name,
            canonical_name=resolution.canonical_name,
            vendor=resolution.vendor,
            product=resolution.product,
            version=version_spec.value if version_spec is not None else resolved_version,
            version_spec=version_spec,
            category=category or resolution.category,
            family=resolution.family,
            confidence=confidence,
            evidence=evidence,
            source=source or self.descriptor.name,
            tool_id=context.tool_id,
            target_id=self._target_id(context),
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
        )
