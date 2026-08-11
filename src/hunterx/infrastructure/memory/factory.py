# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory Tool Integration Factory repositories.

Reference implementations of the factory repository ports without any
database. Used by the platform composition root as the default persistence
backend and by the test suite.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.ports.tool_factory import PackTemplateRepository, ToolPackRepository
from hunterx.domain.tool_factory import IntegrationTemplate, ToolPack


class InMemoryPackTemplateRepository(PackTemplateRepository):
    """In-memory :class:`PackTemplateRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, IntegrationTemplate] = {}

    def save(self, template: IntegrationTemplate) -> None:
        """Persist (insert or update) an integration template."""
        self._store[template.template_id] = template

    def get(self, template_id: str) -> IntegrationTemplate | None:
        """Return a template by identifier, or ``None`` if absent."""
        return self._store.get(template_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[IntegrationTemplate]:
        """Return a page of templates ordered by registration time."""
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, template_id: str) -> None:
        """Delete a template, raising when absent."""
        if template_id not in self._store:
            raise NotFoundError("IntegrationTemplate", template_id)
        del self._store[template_id]


class InMemoryToolPackRepository(ToolPackRepository):
    """In-memory :class:`ToolPackRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, ToolPack] = {}

    def save(self, pack: ToolPack) -> None:
        """Persist (insert or update) a generated tool integration pack."""
        self._store[pack.pack_id] = pack

    def get(self, pack_id: str) -> ToolPack | None:
        """Return a pack by identifier, or ``None`` if absent."""
        return self._store.get(pack_id)

    def list(self, *, vendor: str | None = None, limit: int = 100, offset: int = 0) -> Sequence[ToolPack]:
        """Return a page of packs, optionally filtered by vendor."""
        values = [p for p in self._store.values() if vendor is None or p.vendor == vendor]
        return values[offset : offset + limit]

    def delete(self, pack_id: str) -> None:
        """Delete a pack, raising when absent."""
        if pack_id not in self._store:
            raise NotFoundError("ToolPack", pack_id)
        del self._store[pack_id]


def build_in_memory_factory_repositories() -> dict[str, object]:
    """Build in-memory factory repositories keyed by role name."""
    return {
        "pack_templates": InMemoryPackTemplateRepository(),
        "tool_packs": InMemoryToolPackRepository(),
    }
