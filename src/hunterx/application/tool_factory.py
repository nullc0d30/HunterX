# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory application service.

Framework-agnostic use-case facade over the Tool Integration Factory for API
and CLI layers.
"""

from __future__ import annotations

from hunterx.domain.exceptions import ToolPackNotFoundError
from hunterx.domain.ports.tool_factory import PackTemplateRepository, ToolPackRepository
from hunterx.domain.tool_factory import (
    CompatibilityMatrix,
    IntegrationTemplate,
    PackValidationReport,
    ToolPack,
    ToolPackSpec,
)
from hunterx.shared.result import Result
from hunterx.tools.factory.api import ToolIntegrationFactory


class ToolFactoryService:
    """Application service exposing Tool Integration Factory use cases."""

    def __init__(
        self,
        factory: ToolIntegrationFactory | None = None,
        *,
        pack_repository: ToolPackRepository | None = None,
        template_repository: PackTemplateRepository | None = None,
    ) -> None:
        self._factory = factory or ToolIntegrationFactory(
            pack_repository=pack_repository,
            template_repository=template_repository,
        )

    @property
    def factory(self) -> ToolIntegrationFactory:
        """Return the underlying factory."""
        return self._factory

    def generate(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a Tool Integration Pack for ``spec``."""
        return self._factory.generate(spec)

    def generate_and_validate(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a pack and require the quality gates to pass."""
        return self._factory.generate_and_validate(spec)

    def validate(self, pack: ToolPack) -> PackValidationReport:
        """Validate a pack against the standard layout."""
        return self._factory.validate(pack)

    def accept(self, pack: ToolPack) -> bool:
        """Return ``True`` when a pack passes the quality gates."""
        return self._factory.accept(pack)

    def require_acceptable(self, pack: ToolPack) -> ToolPack:
        """Raise :class:`PackValidationError` when the pack is not acceptable."""
        return self._factory.assert_acceptable(pack)

    def register_template(self, template: IntegrationTemplate) -> IntegrationTemplate:
        """Register an integration template override."""
        return self._factory.register_template(template)

    def list_templates(self) -> list[IntegrationTemplate]:
        """List every known integration template."""
        return self._factory.list_templates()

    def pack_layout(self) -> dict[str, str]:
        """Return the standard pack layout."""
        return self._factory.pack_layout()

    def required_files(self) -> list[str]:
        """Return the required pack files."""
        return self._factory.required_files()

    def quality_gates(self) -> list[str]:
        """Return the quality-gate files."""
        return self._factory.quality_gates()

    def compatibility_matrix(self, spec: ToolPackSpec) -> CompatibilityMatrix:
        """Build the compatibility matrix for ``spec``."""
        return self._factory.compatibility_matrix(spec)

    def list_packs(self, *, vendor: str | None = None) -> list[ToolPack]:
        """List generated packs, optionally filtered by vendor."""
        return self._factory.list_packs(vendor=vendor)

    def get_pack(self, pack_id: str) -> ToolPack:
        """Return a persisted pack, raising when unknown."""
        pack = self._factory.get(pack_id)
        if pack is None:
            raise ToolPackNotFoundError(pack_id)
        return pack

    def delete_pack(self, pack_id: str) -> None:
        """Delete a persisted pack."""
        self._factory.delete(pack_id)
