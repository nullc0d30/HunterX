# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security policy.

Declarative policy rules that the security manager evaluates: which roles may
perform which permission. Kept as pure data so it can be loaded from
configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class SecurityPolicy:
    """A declarative access policy.

    Attributes:
        roles: mapping of role name to the permissions it grants.
        default_deny: when ``True`` (recommended), unlisted permissions are denied.

    """

    roles: dict[str, frozenset[str]] = field(default_factory=dict)
    default_deny: bool = True

    @classmethod
    def from_mapping(cls, mapping: dict[str, Any]) -> SecurityPolicy:
        """Build a policy from a plain mapping ``{role: [permissions]}``."""
        roles = {
            str(role): frozenset(str(perm) for perm in permissions)
            for role, permissions in (mapping.get("roles", {}) or {}).items()
        }
        return cls(roles=roles, default_deny=bool(mapping.get("default_deny", True)))

    def allows(self, role: str, permission: str) -> bool:
        """Return ``True`` when ``role`` may perform ``permission``."""
        granted = self.roles.get(role)
        if granted is None:
            return False
        if permission in granted:
            return True
        return not self.default_deny
