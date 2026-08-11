# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool lifecycle manager.

Coordinates the full lifecycle of a tool: registration, installation,
verification, updates, removal, version compatibility and health monitoring.
The manager drives the state machine and records lifecycle outcomes.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolNotFoundError, ToolRegistrationError
from hunterx.domain.tool_intelligence import (
    ToolMetadata,
    ToolRuntimeState,
    ToolState,
)
from hunterx.shared.time import utcnow_iso
from hunterx.tools.intelligence.health import ToolHealthMonitor
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.state import ToolStateMachine


class ToolLifecycleManager:
    """Manage tool lifecycle and keep runtime state consistent.

    Usage::

        lifecycle = ToolLifecycleManager(registry, state_machine, health)
        lifecycle.register(metadata)
        lifecycle.install("nuclei", version="3.2.0")
        lifecycle.verify("nuclei")
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        state_machine: ToolStateMachine,
        health: ToolHealthMonitor,
    ) -> None:
        self._registry = registry
        self._state_machine = state_machine
        self._health = health

    def register(self, metadata: ToolMetadata) -> None:
        """Register a new tool in the REGISTERED state."""
        self._registry.register_metadata(metadata)

    def unregister(self, tool_id: str) -> None:
        """Remove a tool and all of its intelligence records.

        Raises:
            ToolNotFoundError: if the tool is not registered.

        """
        if not self._registry.remove_tool(tool_id):
            raise ToolNotFoundError(tool_id)

    def install(self, tool_id: str, *, version: str = "") -> ToolRuntimeState:
        """Move ``tool_id`` to INSTALLED, recording the installed version."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.INSTALLED, tool_id=tool_id
        )
        state.state = target
        if version:
            state.installed_version = version
        state.installed_at = utcnow_iso()
        state.last_error = ""
        self._registry.set_state(state)
        return state

    def verify(self, tool_id: str, *, ok: bool = True) -> ToolRuntimeState:
        """Verify an installed tool and move to VERIFIED when ``ok``."""
        state = self._require_state(tool_id)
        if not ok:
            self._health.record_failure(tool_id, crash=False)
            state.last_error = "verification failed"
            self._registry.set_state(state)
            return state
        target = self._state_machine.transition(
            state.state, ToolState.VERIFIED, tool_id=tool_id
        )
        state.state = target
        state.last_verified_at = utcnow_iso()
        state.last_error = ""
        self._registry.set_state(state)
        return state

    def make_available(self, tool_id: str) -> ToolRuntimeState:
        """Move a verified tool to AVAILABLE."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.AVAILABLE, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        return state

    def start(self, tool_id: str) -> ToolRuntimeState:
        """Move an available tool to RUNNING."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.RUNNING, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        return state

    def complete(self, tool_id: str) -> ToolRuntimeState:
        """Record a successful run (RUNNING → COMPLETED)."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.COMPLETED, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        self._health.record_success(tool_id)
        return state

    def fail(self, tool_id: str) -> ToolRuntimeState:
        """Record a failed run (RUNNING → FAILED)."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.FAILED, tool_id=tool_id
        )
        state.state = target
        state.last_error = "execution failed"
        self._registry.set_state(state)
        self._health.record_failure(tool_id, crash=True)
        return state

    def disable(self, tool_id: str) -> ToolRuntimeState:
        """Disable a tool (any non-running state → DISABLED)."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.DISABLED, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        return state

    def enable(self, tool_id: str) -> ToolRuntimeState:
        """Re-enable a disabled tool (DISABLED → AVAILABLE)."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.AVAILABLE, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        return state

    def deprecate(self, tool_id: str) -> ToolRuntimeState:
        """Mark a tool as DEPRECATED (from any usable state)."""
        state = self._require_state(tool_id)
        target = self._state_machine.transition(
            state.state, ToolState.DEPRECATED, tool_id=tool_id
        )
        state.state = target
        self._registry.set_state(state)
        return state

    def update(self, tool_id: str, *, version: str = "") -> ToolRuntimeState:
        """Update an installed tool to ``version`` (re-verify after)."""
        state = self._require_state(tool_id)
        if not self._state_machine.is_usable(state.state):
            raise ToolRegistrationError(
                tool_id, f"cannot update a tool in state '{state.state.value}'"
            )
        if version:
            state.installed_version = version
        state.state = self._state_machine.transition(
            state.state, ToolState.INSTALLED, tool_id=tool_id
        )
        state.last_verified_at = ""
        state.last_error = ""
        self._registry.set_state(state)
        return state

    def is_usable(self, tool_id: str) -> bool:
        """Return ``True`` when the tool is installed and usable."""
        state = self._registry.get_state(tool_id)
        if state is None:
            return False
        return self._state_machine.is_usable(state.state)

    def _require_state(self, tool_id: str) -> ToolRuntimeState:
        state = self._registry.get_state(tool_id)
        if state is None:
            raise ToolNotFoundError(tool_id)
        return state
