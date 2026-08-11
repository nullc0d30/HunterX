# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""In-memory Tool Integration Factory repositories and fixtures.

Test doubles implementing the factory repository ports without any database.
Used by unit tests and embedded/development wiring.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.exceptions import NotFoundError
from hunterx.domain.ports.tool_factory import PackTemplateRepository, ToolPackRepository
from hunterx.domain.tool_factory import IntegrationTemplate, ToolPack
from hunterx.tools.factory.api import ToolIntegrationFactory


class InMemoryPackTemplateRepository(PackTemplateRepository):
    """In-memory :class:`PackTemplateRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, IntegrationTemplate] = {}

    def save(self, template: IntegrationTemplate) -> None:
        self._store[template.template_id] = template

    def get(self, template_id: str) -> IntegrationTemplate | None:
        return self._store.get(template_id)

    def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[IntegrationTemplate]:
        values = list(self._store.values())
        return values[offset : offset + limit]

    def delete(self, template_id: str) -> None:
        if template_id not in self._store:
            raise NotFoundError("IntegrationTemplate", template_id)
        del self._store[template_id]


class InMemoryToolPackRepository(ToolPackRepository):
    """In-memory :class:`ToolPackRepository`."""

    def __init__(self) -> None:
        self._store: dict[str, ToolPack] = {}

    def save(self, pack: ToolPack) -> None:
        self._store[pack.pack_id] = pack

    def get(self, pack_id: str) -> ToolPack | None:
        return self._store.get(pack_id)

    def list(self, *, vendor: str | None = None, limit: int = 100, offset: int = 0) -> Sequence[ToolPack]:
        values = [p for p in self._store.values() if vendor is None or p.vendor == vendor]
        return values[offset : offset + limit]

    def delete(self, pack_id: str) -> None:
        if pack_id not in self._store:
            raise NotFoundError("ToolPack", pack_id)
        del self._store[pack_id]


def build_in_memory_factory_repositories() -> dict[str, object]:
    """Build in-memory factory repositories keyed by role name."""
    return {
        "pack_templates": InMemoryPackTemplateRepository(),
        "tool_packs": InMemoryToolPackRepository(),
    }


def make_factory(
    *,
    pack_repository: ToolPackRepository | None = None,
    template_repository: PackTemplateRepository | None = None,
) -> ToolIntegrationFactory:
    """Build a fully wired :class:`ToolIntegrationFactory` over in-memory stores."""
    if pack_repository is None:
        pack_repository = InMemoryToolPackRepository()
    if template_repository is None:
        template_repository = InMemoryPackTemplateRepository()
    return ToolIntegrationFactory(
        pack_repository=pack_repository,  # type: ignore[arg-type]
        template_repository=template_repository,  # type: ignore[arg-type]
    )
