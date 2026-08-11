# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory exception hierarchy.

Errors raised by the Tool Integration Factory, which generates standardized
Tool Integration Packs. Every error carries ``HunterXErrorCode.FACTORY`` and
derives from :class:`ToolFactoryError`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from hunterx.domain.exceptions.base import HunterXErrorCode
from hunterx.domain.exceptions.domain import DomainError

if TYPE_CHECKING:
    from hunterx.domain.tool_factory import ValidationIssue


class ToolFactoryError(DomainError):
    """Base for errors raised by the Tool Integration Factory."""

    code = HunterXErrorCode.FACTORY


class InvalidToolPackSpecError(ToolFactoryError):
    """Raised when a pack specification is malformed."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PackGenerationError(ToolFactoryError):
    """Raised when a pack cannot be generated from a valid spec."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ToolPackNotFoundError(ToolFactoryError):
    """Raised when a persisted tool integration pack is unknown."""

    def __init__(self, pack_id: str) -> None:
        super().__init__(f"Tool integration pack '{pack_id}' was not found.")
        self.pack_id = pack_id


class DuplicatePackError(ToolFactoryError):
    """Raised when a pack with the same identifier is already registered."""

    def __init__(self, pack_id: str) -> None:
        super().__init__(f"Tool integration pack '{pack_id}' is already registered.")
        self.pack_id = pack_id


class PackValidationError(ToolFactoryError):
    """Raised when a generated pack fails validation or quality gates.

    Attributes:
        issues: the validation issues that failed the pack.

    """

    def __init__(self, message: str, *, issues: Sequence[ValidationIssue]) -> None:
        super().__init__(message)
        self.issues = tuple(issues)


class GeneratorNotFoundError(ToolFactoryError):
    """Raised when an unknown generator is requested."""

    def __init__(self, name: str) -> None:
        super().__init__(f"Pack generator '{name}' was not found.")
        self.name = name


class TemplateNotFoundError(ToolFactoryError):
    """Raised when a requested integration template is unknown."""

    def __init__(self, template_id: str) -> None:
        super().__init__(f"Integration template '{template_id}' was not found.")
        self.template_id = template_id


class TemplateRenderError(ToolFactoryError):
    """Raised when a template cannot be rendered for a pack."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PackagingError(ToolFactoryError):
    """Raised when pack packaging metadata cannot be produced."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class CompatibilityError(ToolFactoryError):
    """Raised when a pack declares an incompatible version matrix."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
