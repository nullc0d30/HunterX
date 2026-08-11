# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests: authorization and secret handling."""

from __future__ import annotations

import pytest

from hunterx.infrastructure.secrets import InMemorySecrets
from hunterx.security.manager import Actor, PermissionDeniedError, SecurityManager
from hunterx.security.policies import SecurityPolicy


def _manager() -> SecurityManager:
    policy = SecurityPolicy(
        roles={
            "admin": frozenset({"mission.create", "mission.read", "secrets.read"}),
            "analyst": frozenset({"mission.read"}),
        },
        default_deny=True,
    )
    return SecurityManager(policy, InMemorySecrets())


class TestAuthorization:
    def test_admin_can_create(self) -> None:
        manager = _manager()
        manager.authorize(Actor("a", roles=("admin",)), "mission.create")

    def test_analyst_denied_create(self) -> None:
        manager = _manager()
        with pytest.raises(PermissionDeniedError):
            manager.authorize(Actor("a", roles=("analyst",)), "mission.create")

    def test_unknown_role_denied(self) -> None:
        manager = _manager()
        assert manager.can(Actor("x", roles=("ghost",)), "mission.read") is False

    def test_default_role_denies(self) -> None:
        manager = _manager()
        assert manager.can(Actor("x"), "mission.read") is False


class TestSecrets:
    def test_resolve_secret_authorized(self) -> None:
        manager = _manager()
        manager._secrets.set("API_KEY", "abc123")
        assert manager.resolve_secret(Actor("a", roles=("admin",)), "API_KEY") == "abc123"

    def test_resolve_secret_denied(self) -> None:
        manager = _manager()
        manager._secrets.set("API_KEY", "abc123")
        with pytest.raises(PermissionDeniedError):
            manager.resolve_secret(Actor("a", roles=("analyst",)), "API_KEY")
