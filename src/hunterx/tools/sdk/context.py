# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution context builder.

Builds :class:`ExecutionContext` instances with deterministic identifiers and
sane defaults. Every execution created by the framework goes through this
factory so identifiers (execution id, correlation id) and timestamps stay
consistent.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from hunterx.domain.execution import (
    ExecutionContext,
    ExecutionEnvironment,
    ResourceLimits,
    RetryPolicy,
)
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ExecutionContextBuilder:
    """Fluent builder for :class:`ExecutionContext`.

    Usage::

        context = (
            ExecutionContextBuilder(tool_id="nmap", target="10.0.0.5")
            .with_target_type("host")
            .with_timeout(120.0)
            .build()
        )

    Required values are ``tool_id`` and ``target``; everything else has a
    safe default.
    """

    def __init__(self, tool_id: str, target: str) -> None:
        self._context = ExecutionContext(tool_id=tool_id, target=target)

    @classmethod
    def from_context(cls, template: ExecutionContext) -> ExecutionContextBuilder:
        """Start from an existing context (copying every field)."""
        builder = cls(tool_id=template.tool_id, target=template.target)
        builder._context = replace(template)
        return builder

    def with_execution_id(self, execution_id: str) -> ExecutionContextBuilder:
        """Override the auto-generated execution id."""
        self._context = _replace(self._context, execution_id=execution_id)
        return self

    def with_mission(self, mission_id: str) -> ExecutionContextBuilder:
        """Set the owning mission id."""
        self._context = _replace(self._context, mission_id=mission_id)
        return self

    def with_target(self, target: str) -> ExecutionContextBuilder:
        """Set the target being assessed."""
        self._context = _replace(self._context, target=target)
        return self

    def with_target_type(self, target_type: str) -> ExecutionContextBuilder:
        """Set the canonical target kind."""
        self._context = _replace(self._context, target_type=target_type)
        return self

    def with_profile(self, profile: str) -> ExecutionContextBuilder:
        """Set the mission profile name."""
        self._context = _replace(self._context, profile=profile)
        return self

    def with_configuration(self, configuration: str) -> ExecutionContextBuilder:
        """Set the configuration/profile reference."""
        self._context = _replace(self._context, configuration=configuration)
        return self

    def with_tool_version(self, tool_version: str) -> ExecutionContextBuilder:
        """Set the requested tool version."""
        self._context = _replace(self._context, tool_version=tool_version)
        return self

    def with_environment(self, environment: ExecutionEnvironment) -> ExecutionContextBuilder:
        """Set the execution environment description."""
        self._context = _replace(self._context, environment=environment)
        return self

    def with_permissions(self, permissions: tuple[str, ...]) -> ExecutionContextBuilder:
        """Set the granted permission flags."""
        self._context = _replace(self._context, permissions=permissions)
        return self

    def with_timeout(self, timeout_seconds: float) -> ExecutionContextBuilder:
        """Set the execution timeout in seconds."""
        self._context = _replace(self._context, timeout_seconds=timeout_seconds)
        return self

    def with_retry_policy(self, retry_policy: RetryPolicy) -> ExecutionContextBuilder:
        """Set the retry policy."""
        self._context = _replace(self._context, retry_policy=retry_policy)
        return self

    def with_resource_limits(self, resource_limits: ResourceLimits) -> ExecutionContextBuilder:
        """Set the resource budget."""
        self._context = _replace(self._context, resource_limits=resource_limits)
        return self

    def with_directories(
        self,
        *,
        working_directory: str = "",
        output_directory: str = "",
        temp_directory: str = "",
    ) -> ExecutionContextBuilder:
        """Set scratch, artifact and temporary directories."""
        self._context = _replace(
            self._context,
            working_directory=working_directory,
            output_directory=output_directory,
            temp_directory=temp_directory,
        )
        return self

    def with_correlation_id(self, correlation_id: str) -> ExecutionContextBuilder:
        """Set the correlation id (batch/mission wide)."""
        self._context = _replace(self._context, correlation_id=correlation_id)
        return self

    def with_parameters(self, parameters: dict[str, Any]) -> ExecutionContextBuilder:
        """Set the tool parameters."""
        self._context = _replace(self._context, parameters=dict(parameters))
        return self

    def build(self) -> ExecutionContext:
        """Return the assembled execution context.

        The execution id is auto-generated when not overridden and the
        correlation id falls back to the execution id when unset.
        """
        context = self._context
        if not context.correlation_id:
            context = _replace(context, correlation_id=context.execution_id)
        return context


class ExecutionIDFactory:
    """Generate execution and correlation identifiers."""

    def new_execution_id(self) -> str:
        """Return a fresh ULID for an execution."""
        return generate_id()

    def new_correlation_id(self) -> str:
        """Return a fresh ULID for a correlation group."""
        return generate_id()

    def timestamp(self) -> str:
        """Return the current UTC ISO-8601 timestamp."""
        return utcnow_iso()


def _replace(context: ExecutionContext, **changes: Any) -> ExecutionContext:
    """Return a copy of ``context`` with ``changes`` applied (frozen model)."""
    return replace(context, **changes)
