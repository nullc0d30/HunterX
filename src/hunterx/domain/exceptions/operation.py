# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Operation/runtime exceptions."""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXError, HunterXErrorCode
from hunterx.domain.exceptions.infrastructure import NotFoundError


class OperationError(HunterXError):
    """Base for errors raised while executing operations."""

    code = HunterXErrorCode.OPERATION


class MissionNotFoundError(NotFoundError):
    """Raised when a mission does not exist."""

    def __init__(self, mission_id: str) -> None:
        super().__init__("Mission", mission_id)


class MissionAlreadyRunningError(OperationError):
    """Raised when an operation targets a running mission."""

    code = HunterXErrorCode.MISSION

    def __init__(self, mission_id: str) -> None:
        super().__init__(f"Mission '{mission_id}' is already running.")
        self.mission_id = mission_id


class PluginLoadError(OperationError):
    """Raised when a plugin cannot be loaded."""

    code = HunterXErrorCode.PLUGIN


class PluginExecutionError(OperationError):
    """Raised when a plugin raises while executing."""

    code = HunterXErrorCode.PLUGIN


class PluginNotFoundError(OperationError):
    """Raised when a plugin is not registered."""

    code = HunterXErrorCode.PLUGIN

    def __init__(self, name: str) -> None:
        super().__init__(f"Plugin '{name}' was not found.")
        self.name = name


class ToolExecutionError(OperationError):
    """Raised when a tool raises while executing."""

    code = HunterXErrorCode.TOOL


class ToolNotFoundError(OperationError):
    """Raised when a tool is not registered."""

    code = HunterXErrorCode.TOOL

    def __init__(self, name: str) -> None:
        super().__init__(f"Tool '{name}' was not found.")
        self.name = name


class ToolRegistrationError(OperationError):
    """Raised when tool registration violates a registry invariant."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, reason: str) -> None:
        super().__init__(f"Tool '{tool_id}' cannot be registered: {reason}")
        self.tool_id = tool_id
        self.reason = reason


class ToolStateTransitionError(OperationError):
    """Raised when a tool state transition is not permitted."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, source: str, target: str, reason: str = "") -> None:
        detail = f" ({reason})" if reason else ""
        super().__init__(
            f"Tool '{tool_id}' cannot transition from '{source}' to '{target}'{detail}."
        )
        self.tool_id = tool_id
        self.source = source
        self.target = target


class ToolSelectionError(OperationError):
    """Raised when tool selection cannot be performed."""

    code = HunterXErrorCode.TOOL

    def __init__(self, reason: str) -> None:
        super().__init__(f"Tool selection failed: {reason}")
        self.reason = reason


class ExecutionError(OperationError):
    """Base for errors raised by the tool execution framework."""

    code = HunterXErrorCode.TOOL


class ToolTimeoutError(ExecutionError):
    """Raised when an execution exceeds its configured timeout."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, timeout_seconds: float) -> None:
        super().__init__(
            f"Tool '{tool_id}' exceeded its timeout of {timeout_seconds:g}s."
        )
        self.tool_id = tool_id
        self.timeout_seconds = timeout_seconds


class ToolCancellationError(ExecutionError):
    """Raised when an execution is cancelled before completing."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, reason: str = "cancelled") -> None:
        super().__init__(f"Tool '{tool_id}' execution was cancelled: {reason}.")
        self.tool_id = tool_id
        self.reason = reason


class ToolRetryableError(ExecutionError):
    """Raised when an execution fails in a way that may succeed on retry."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, message: str) -> None:
        super().__init__(f"Tool '{tool_id}' failed with a retryable error: {message}")
        self.tool_id = tool_id


class ToolInstallationError(ExecutionError):
    """Raised when a tool cannot be installed or uninstalled."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, reason: str) -> None:
        super().__init__(f"Tool '{tool_id}' installation failed: {reason}")
        self.tool_id = tool_id
        self.reason = reason


class ToolDependencyError(ExecutionError):
    """Raised when a tool's dependencies cannot be satisfied."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, missing: list[str] | tuple[str, ...]) -> None:
        super().__init__(
            f"Tool '{tool_id}' has unsatisfied dependencies: {', '.join(missing)}"
        )
        self.tool_id = tool_id
        self.missing = tuple(missing)


class ToolHealthError(ExecutionError):
    """Raised when a health check determines a tool is unusable."""

    code = HunterXErrorCode.TOOL

    def __init__(self, tool_id: str, reason: str) -> None:
        super().__init__(f"Tool '{tool_id}' failed health check: {reason}")
        self.tool_id = tool_id
        self.reason = reason


class ToolLockError(ExecutionError):
    """Raised when a tool lock cannot be acquired."""

    code = HunterXErrorCode.TOOL

    def __init__(self, key: str, reason: str = "lock is held") -> None:
        super().__init__(f"Tool lock '{key}' could not be acquired: {reason}.")
        self.key = key
        self.reason = reason


class ToolQueueError(ExecutionError):
    """Raised when a tool execution cannot be queued."""

    code = HunterXErrorCode.TOOL

    def __init__(self, reason: str) -> None:
        super().__init__(f"Tool queue error: {reason}")
        self.reason = reason


class ScheduleConflictError(OperationError):
    """Raised when a schedule cannot be applied."""

    code = HunterXErrorCode.SCHEDULER


class ReportRenderError(OperationError):
    """Raised when a report cannot be rendered."""

    code = HunterXErrorCode.REPORTING


class AuthenticationError(OperationError):
    """Raised when authentication fails."""

    code = HunterXErrorCode.AUTHENTICATION


class AuthorizationError(OperationError):
    """Raised when an actor lacks permission."""

    code = HunterXErrorCode.AUTHORIZATION

    def __init__(self, message: str = "Insufficient permissions.") -> None:
        super().__init__(message)
