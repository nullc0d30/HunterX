# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security manager facade."""

from __future__ import annotations

from hunterx.domain.ports.services import SecretsPort
from hunterx.infrastructure.secrets import EnvironmentSecrets, InMemorySecrets
from hunterx.security.manager import Actor, PermissionDeniedError, SecurityManager
from hunterx.security.policies import SecurityPolicy

__all__ = [
    "SecretsPort",
    "EnvironmentSecrets",
    "InMemorySecrets",
    "Actor",
    "PermissionDeniedError",
    "SecurityManager",
    "SecurityPolicy",
]
