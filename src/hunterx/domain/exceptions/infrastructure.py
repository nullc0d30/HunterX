# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Infrastructure/adapters exceptions."""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXError, HunterXErrorCode


class InfrastructureError(HunterXError):
    """Base for all infrastructure/adapter errors."""

    code = HunterXErrorCode.PERSISTENCE


class PersistenceError(InfrastructureError):
    """Raised when a persistence operation fails."""

    code = HunterXErrorCode.PERSISTENCE


class NotFoundError(PersistenceError):
    """Raised when a requested record does not exist."""

    def __init__(self, entity: str, identifier: str) -> None:
        super().__init__(f"{entity} '{identifier}' was not found.")
        self.entity = entity
        self.identifier = identifier


class DuplicateRegistrationError(InfrastructureError):
    """Raised when a service/key is registered twice in a container."""

    def __init__(self, key: object) -> None:
        super().__init__(f"Duplicate registration for {key!r}.")
        self.key = key


class RegistrationNotFoundError(InfrastructureError):
    """Raised when a service/key cannot be resolved."""

    def __init__(self, key: object) -> None:
        super().__init__(f"No registration found for {key!r}.")
        self.key = key


class CacheError(InfrastructureError):
    """Raised when a cache operation fails."""

    code = HunterXErrorCode.CACHE


class QueueError(InfrastructureError):
    """Raised when a queue operation fails."""

    code = HunterXErrorCode.QUEUE


class ConnectionError(InfrastructureError):
    """Raised when an external system cannot be reached."""

    code = HunterXErrorCode.CONNECTION


class SecretResolutionError(InfrastructureError):
    """Raised when a secret cannot be resolved."""

    code = HunterXErrorCode.SECRET


class SandboxError(InfrastructureError):
    """Raised when sandbox isolation is violated or unavailable."""

    code = HunterXErrorCode.SANDBOX
