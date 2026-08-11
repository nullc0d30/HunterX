# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Execution sandbox.

Isolates tool execution: permission enforcement, filesystem isolation via
per-execution temporary directories, environment isolation (secret-safe env
construction) and secret masking in captured output. The sandbox is the single
place where execution security policies are applied.
"""

from __future__ import annotations

import os
import re
import tempfile
from typing import Any

from hunterx.domain.exceptions import SandboxError
from hunterx.domain.execution import ExecutionContext, ExecutionOutput
from hunterx.plugins.manifest import PermissionFlag
from hunterx.tools.sandbox import ToolSandboxPolicy


class ExecutionSandbox:
    """Apply execution isolation policies to a tool run.

    Usage::

        sandbox = ExecutionSandbox()
        sandbox.enforce_permission(context, PermissionFlag.NETWORK)
        temp_dir = sandbox.create_temp_directory(context)
        env = sandbox.prepare_environment(context, secrets={"API_KEY": "..."})
        masked = sandbox.mask_secrets(output, secrets)
    """

    def __init__(
        self,
        policy: ToolSandboxPolicy | None = None,
        *,
        platform_permissions: frozenset[PermissionFlag] | None = None,
    ) -> None:
        if policy is not None:
            self._policy = policy
        elif platform_permissions is not None:
            self._policy = ToolSandboxPolicy(platform_permissions=platform_permissions)
        else:
            self._policy = ToolSandboxPolicy(platform_permissions=frozenset(PermissionFlag))

    # -- permission isolation ----------------------------------------------

    def enforce_permission(self, context: ExecutionContext, flag: PermissionFlag) -> None:
        """Raise :class:`SandboxError` when the execution lacks ``flag``.

        The permission must be listed in the context's ``permissions`` and be
        allowed by the platform policy.
        """
        if flag == PermissionFlag.NONE:
            return
        if flag.value not in context.permissions:
            raise SandboxError(
                f"Tool '{context.tool_id}' lacks permission '{flag.value}' for this execution."
            )
        self._allow_platform(context.tool_id, flag)

    def grants(self, context: ExecutionContext, flag: PermissionFlag) -> bool:
        """Return ``True`` when ``flag`` is granted for this execution."""
        try:
            self.enforce_permission(context, flag)
        except SandboxError:
            return False
        return True

    # -- filesystem isolation ----------------------------------------------

    def create_temp_directory(self, context: ExecutionContext) -> str:
        """Create and return an isolated temporary directory for the execution.

        The directory is named after the execution id so artifacts from
        different executions never collide. Tool ids are sanitized so a
        hostile identifier cannot traverse out of the base directory.
        """
        base = context.temp_directory or tempfile.gettempdir()
        path = os.path.join(base, f"hx-{_safe_component(context.tool_id)}-{_safe_component(context.execution_id)}")
        os.makedirs(path, exist_ok=True)
        return path

    def create_output_directory(self, context: ExecutionContext) -> str:
        """Create and return the artifact output directory for the execution."""
        base = context.output_directory or context.temp_directory or tempfile.gettempdir()
        path = os.path.join(base, f"hx-out-{_safe_component(context.execution_id)}")
        os.makedirs(path, exist_ok=True)
        return path

    # -- environment isolation ---------------------------------------------

    def prepare_environment(
        self,
        context: ExecutionContext,
        *,
        secrets: dict[str, str] | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Build the environment variable set for the execution.

        Secrets are only injected when the execution holds the ``secrets``
        permission. The returned mapping must not be mutated by tools.
        """
        environment: dict[str, str] = {
            "HUNTERX_EXECUTION_ID": context.execution_id,
            "HUNTERX_TOOL_ID": context.tool_id,
            "HUNTERX_TARGET": context.target,
            "HUNTERX_CORRELATION_ID": context.correlation_id,
        }
        if extra:
            environment.update(extra)
        if secrets and self.grants(context, PermissionFlag.SECRETS):
            environment.update({f"HUNTERX_SECRET_{name}": value for name, value in secrets.items()})
        return environment

    def sanitized_environment(
        self,
        context: ExecutionContext,
        *,
        secrets: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Return an environment mapping with all secret values removed.

        Useful for logging and telemetry that must never contain secrets.
        """
        environment = self.prepare_environment(context)
        if secrets:
            for name in secrets:
                environment.pop(f"HUNTERX_SECRET_{name}", None)
        return environment

    # -- secret handling -----------------------------------------------------

    def mask_secrets(self, output: ExecutionOutput, secrets: dict[str, str] | None) -> ExecutionOutput:
        """Redact secret values from a copy of ``output``.

        The original output is untouched; a masked copy is returned so raw
        output can still be stored in protected storage.
        """
        if not secrets:
            return output
        patterns = [
            re.compile(re.escape(value)) if re.match(r"^[\w\-._]+$", value, re.ASCII) else re.compile(re.escape(value))
            for value in secrets.values()
            if value
        ]
        if not patterns:
            return output
        masked = ExecutionOutput(
            stdout=_redact(output.stdout, patterns),
            stderr=_redact(output.stderr, patterns),
            exit_code=output.exit_code,
            files=list(output.files),
            json=_redact_json(output.json, patterns),
            xml=_redact(output.xml, patterns),
            csv=[[_redact(cell, patterns) for cell in row] for row in output.csv],
            txt=_redact(output.txt, patterns),
            yaml=_redact(output.yaml, patterns),
            html=_redact(output.html, patterns),
            binary=output.binary,
            screenshots=list(output.screenshots),
            pcap_references=list(output.pcap_references),
            formats=set(output.formats),
        )
        return masked

    # -- helpers --------------------------------------------------------------

    def _allow_platform(self, tool_id: str, flag: PermissionFlag) -> None:
        if flag == PermissionFlag.NONE:
            return
        if flag not in getattr(self._policy, "_platform", frozenset({PermissionFlag.NONE})):
            raise SandboxError(
                f"Platform policy denies '{flag.value}' for tool '{tool_id}'."
            )


_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9_.-]")


def _safe_component(value: str) -> str:
    """Return ``value`` reduced to filesystem-safe characters.

    ``..``, path separators and control characters are replaced so a hostile
    identifier can never traverse out of its base directory.
    """
    component = _UNSAFE_PATH_CHARS.sub("_", value or "")
    component = component.replace("..", "_")
    component = component.strip(".")
    return component[:120] or "exec"


def _redact(text: str, patterns: list[re.Pattern[str]]) -> str:
    masked = text
    for pattern in patterns:
        masked = pattern.sub("[REDACTED]", masked)
    return masked


def _redact_json(payload: dict[str, Any] | None, patterns: list[re.Pattern[str]]) -> dict[str, Any] | None:
    if payload is None:
        return None
    return {key: _redact_value(value, patterns) for key, value in payload.items()}


def _redact_value(value: Any, patterns: list[re.Pattern[str]]) -> Any:
    if isinstance(value, str):
        return _redact(value, patterns)
    if isinstance(value, list):
        return [_redact_value(item, patterns) for item in value]
    if isinstance(value, dict):
        return _redact_json(value, patterns)
    return value
