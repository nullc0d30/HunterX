# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory ports.

Persistence contracts for integration templates and generated tool
integration packs. Adapters implement these (SQL, filesystem, in-memory)
without the factory knowing where records live.
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from hunterx.domain.tool_factory import IntegrationTemplate, ToolPack


class PackTemplateRepository(abc.ABC):
    """Persistence contract for :class:`IntegrationTemplate` records."""

    @abc.abstractmethod
    def save(self, template: IntegrationTemplate) -> None:
        """Persist (insert or update) an integration template."""

    @abc.abstractmethod
    def get(self, template_id: str) -> IntegrationTemplate | None:
        """Return a template by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[IntegrationTemplate]:
        """Return a page of templates ordered by registration time."""

    @abc.abstractmethod
    def delete(self, template_id: str) -> None:
        """Delete a template, raising when absent."""


class ToolPackRepository(abc.ABC):
    """Persistence contract for generated :class:`ToolPack` records."""

    @abc.abstractmethod
    def save(self, pack: ToolPack) -> None:
        """Persist (insert or update) a generated tool integration pack."""

    @abc.abstractmethod
    def get(self, pack_id: str) -> ToolPack | None:
        """Return a pack by identifier, or ``None`` if absent."""

    @abc.abstractmethod
    def list(self, *, vendor: str | None = None, limit: int = 100, offset: int = 0) -> Sequence[ToolPack]:
        """Return a page of packs, optionally filtered by vendor."""

    @abc.abstractmethod
    def delete(self, pack_id: str) -> None:
        """Delete a pack, raising when absent."""
