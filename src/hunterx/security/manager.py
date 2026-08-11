# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security manager.

Provides permission checks, secret resolution and role resolution. The manager
depends on a :class:`~hunterx.domain.ports.services.SecretsPort` for secrets
and a :class:`SecurityPolicy` for authorization rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.exceptions import AuthorizationError
from hunterx.domain.ports.services import SecretsPort
from hunterx.security.policies import SecurityPolicy

#: Canonical permission identifiers used by the platform.
Permission = str

#: Canonical role identifiers.
Role = str


class PermissionDeniedError(AuthorizationError):
    """Raised when an actor lacks a required permission."""


@dataclass(frozen=True, slots=True)
class Actor:
    """An authenticated principal.

    Attributes:
        name: principal identifier.
        roles: roles granted to the principal.

    """

    name: str
    roles: tuple[str, ...] = ()


class SecurityManager:
    """Enforce authorization and resolve secrets safely."""

    def __init__(
        self,
        policy: SecurityPolicy,
        secrets: SecretsPort,
        *,
        default_role: Role = "readonly",
    ) -> None:
        self._policy = policy
        self._secrets = secrets
        self._default_role = default_role

    def authorize(self, actor: Actor, permission: Permission) -> None:
        """Raise :class:`PermissionDeniedError` unless any of the actor's roles grants ``permission``."""
        roles = actor.roles or (self._default_role,)
        if not any(self._policy.allows(role, permission) for role in roles):
            raise PermissionDeniedError(
                f"Actor '{actor.name}' is not allowed to '{permission}'."
            )

    def can(self, actor: Actor, permission: Permission) -> bool:
        """Return ``True`` when the actor may perform ``permission``."""
        try:
            self.authorize(actor, permission)
        except PermissionDeniedError:
            return False
        return True

    def resolve_secret(self, actor: Actor, name: str) -> str:
        """Resolve a secret for an authorized actor.

        Raises:
            PermissionDeniedError: if the actor lacks the ``secrets.read``
                permission.
            SecretResolutionError: if the secret is unavailable.

        """
        self.authorize(actor, "secrets.read")
        return self._secrets.get(name)

    def has_secret(self, name: str) -> bool:
        """Return ``True`` when a secret exists (no authorization required for existence)."""
        return self._secrets.has(name)
