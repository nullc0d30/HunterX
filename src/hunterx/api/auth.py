# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Optional REST API authentication and coarse role enforcement.

The REST API is an *opt-in* control plane: by default it binds to loopback and trusts the local operator (no
authentication).
"""

from __future__ import annotations

from dataclasses import dataclass

#: Paths that never require a key (liveness probes, protocol docs).
_EXEMPT_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})

_ROLE_ADMIN = "admin"
_ROLE_READONLY = "readonly"


@dataclass(frozen=True, slots=True)
class ApiAuthConfig:
    """Runtime API authentication configuration.

    Attributes:
        enabled: whether authentication is enforced.
        api_key: admin key granting full access.
        read_only_key: optional key granting read-only access.

    """

    enabled: bool = False
    api_key: str = ""
    read_only_key: str = ""

    @classmethod
    def disabled(cls) -> ApiAuthConfig:
        """Return the default (disabled) configuration."""
        return cls()

    def role_for(self, presented: str) -> str | None:
        """Return the role for ``presented`` key, or ``None`` when unknown."""
        if not presented:
            return None
        if self.api_key and presented == self.api_key:
            return _ROLE_ADMIN
        if self.read_only_key and presented == self.read_only_key:
            return _ROLE_READONLY
        return None

    def may(self, role: str, method: str) -> bool:
        """Return whether ``role`` may issue ``method``."""
        if method in ("GET", "HEAD", "OPTIONS"):
            return True
        return role == _ROLE_ADMIN

    def exempt(self, path: str) -> bool:
        """Return whether ``path`` is exempt from authentication."""
        return path in _EXEMPT_PATHS or path.startswith("/docs/")


_CONFIG: ApiAuthConfig = ApiAuthConfig.disabled()


def configure_auth(config: ApiAuthConfig | None = None) -> None:
    """Point the shared API authentication config at ``config``.

    Called by :func:`hunterx.api.app.create_app` at startup from settings.
    """
    global _CONFIG
    _CONFIG = config or ApiAuthConfig.disabled()


def auth_config() -> ApiAuthConfig:
    """Return the currently active API authentication configuration."""
    return _CONFIG


__all__ = ["ApiAuthConfig", "auth_config", "configure_auth"]
