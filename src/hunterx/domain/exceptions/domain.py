# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Domain-model exceptions."""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXError, HunterXErrorCode


class DomainError(HunterXError):
    """Base for violations of domain invariants."""

    code = HunterXErrorCode.DOMAIN


class ValidationError(DomainError):
    """Raised when an entity/object fails structural validation."""

    code = HunterXErrorCode.VALIDATION

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class InvalidTargetError(DomainError):
    """Raised when a Target entity violates its invariants."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid target: {message}")


class InvalidFindingError(DomainError):
    """Raised when a Finding entity violates its invariants."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid finding: {message}")


class InvalidMissionError(DomainError):
    """Raised when a Mission entity violates its invariants."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Invalid mission: {message}")
