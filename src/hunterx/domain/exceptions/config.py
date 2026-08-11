# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Configuration-related exceptions."""

from __future__ import annotations

from hunterx.domain.exceptions.base import HunterXError, HunterXErrorCode


class ConfigurationError(HunterXError):
    """Raised when configuration cannot be loaded or applied."""

    code = HunterXErrorCode.CONFIGURATION


class ProfileNotFoundError(ConfigurationError):
    """Raised when a named configuration profile does not exist."""

    def __init__(self, profile: str) -> None:
        super().__init__(f"Configuration profile '{profile}' not found.")
        self.profile = profile


class ValidationConfigError(ConfigurationError):
    """Raised when configuration fails schema validation."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("Configuration validation failed: " + "; ".join(errors))
        self.errors = errors
