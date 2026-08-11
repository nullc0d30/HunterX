# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Plugin runtime context.

Handed to a plugin when it activates or executes. Provides access to the
mission, target, parameters and a sandboxed interaction surface. Secrets are
never exposed directly — only through the redacted secrets resolver.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.shared.masking import mask_secret


@dataclass(slots=True)
class PluginSession:
    """One execution session of a plugin.

    Attributes:
        mission_id: owning mission.
        target: target identifier under investigation.
        parameters: resolved run parameters.

    """

    mission_id: str
    target: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)


class PluginContext:
    """Context object handed to plugin lifecycle and execution calls.

    Wraps the session plus optional read-only collaborators (secrets resolver
    and event emitter). Kept minimal so plugin authors have a stable, small
    surface.
    """

    def __init__(
        self,
        session: PluginSession,
        *,
        secrets_resolver: Any = None,
        emitter: Any = None,
    ) -> None:
        self._session = session
        self._secrets_resolver = secrets_resolver
        self._emitter = emitter

    @property
    def session(self) -> PluginSession:
        """Return the current execution session."""
        return self._session

    @property
    def mission_id(self) -> str:
        """Return the owning mission identifier."""
        return self._session.mission_id

    @property
    def target(self) -> str:
        """Return the target identifier under investigation."""
        return self._session.target

    def param(self, name: str, default: Any = None) -> Any:
        """Return a resolved run parameter by name."""
        return self._session.parameters.get(name, default)

    def secret(self, name: str) -> str:
        """Resolve a secret for the plugin, never logging it.

        Raises:
            hunterx.domain.exceptions.SecretResolutionError: if the secret is
                unavailable or the plugin lacks the ``secrets`` permission.

        """
        if self._secrets_resolver is None:
            raise RuntimeError("Secrets access is not enabled in this context.")
        return self._secrets_resolver(name)

    def masked_secret(self, name: str) -> str:
        """Return a masked form of a resolved secret for display/logging."""
        try:
            return mask_secret(self.secret(name))
        except Exception:
            return ""

    def emit(self, event_type: str, payload: dict[str, Any]) -> None:
        """Emit a domain event from the plugin."""
        if self._emitter is None:
            return
        self._emitter(event_type, payload)


class PluginResult:
    """A structured outcome returned by a plugin execution.

    Attributes:
        ok: whether execution succeeded.
        value: JSON-serializable result data.
        error: error message when ``ok`` is ``False``.

    """

    def __init__(self, ok: bool, value: dict[str, Any] | None = None, error: str = "") -> None:
        self.ok = ok
        self.value = value or {}
        self.error = error

    @classmethod
    def success(cls, value: dict[str, Any]) -> PluginResult:
        """Construct a successful result."""
        return cls(ok=True, value=value)

    @classmethod
    def failure(cls, message: str) -> PluginResult:
        """Construct a failed result."""
        return cls(ok=False, error=message)
