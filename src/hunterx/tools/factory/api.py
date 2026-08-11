# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory facade.

The public entry point for generating, validating and managing Tool
Integration Packs. Composes the generator engine, integration template store,
validator, compatibility validator and pack repository, and exposes the
standard pack layout and quality gates.
"""

from __future__ import annotations

from hunterx.domain.exceptions import (
    NotFoundError,
    PackValidationError,
    ToolPackNotFoundError,
)
from hunterx.domain.ports.tool_factory import PackTemplateRepository, ToolPackRepository
from hunterx.domain.tool_factory import (
    CompatibilityMatrix,
    IntegrationTemplate,
    PackValidationReport,
    ToolPack,
    ToolPackSpec,
)
from hunterx.shared.result import Result
from hunterx.tools.factory.compatibility import CompatibilityValidator
from hunterx.tools.factory.engine import ToolPackGeneratorEngine
from hunterx.tools.factory.layout import (
    GENERATOR_VERSION,
    PACK_LAYOUT,
    quality_gate_files,
    required_files,
)
from hunterx.tools.factory.templates import PackTemplateStore
from hunterx.tools.factory.validator import ToolPackValidator


class ToolIntegrationFactory:
    """Generates standardized Tool Integration Packs for future tools."""

    generator_version = GENERATOR_VERSION

    def __init__(
        self,
        *,
        engine: ToolPackGeneratorEngine | None = None,
        templates: PackTemplateStore | None = None,
        validator: ToolPackValidator | None = None,
        compatibility: CompatibilityValidator | None = None,
        pack_repository: ToolPackRepository | None = None,
        template_repository: PackTemplateRepository | None = None,
    ) -> None:
        self._templates = templates or PackTemplateStore(template_repository)
        self._validator = validator or ToolPackValidator()
        self._compatibility = compatibility or CompatibilityValidator()
        self._repository = pack_repository
        self._engine = engine or ToolPackGeneratorEngine(
            templates=self._templates,
            validator=self._validator,
            compatibility=self._compatibility,
            repository=pack_repository,
        )

    # -- generation ---------------------------------------------------------

    def generate(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a Tool Integration Pack for ``spec``."""
        return self._engine.generate(spec)

    def generate_pack(self, spec: ToolPackSpec) -> ToolPack:
        """Generate a pack, raising on structural failure."""
        return self._engine.generate_pack(spec)

    def generate_and_validate(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a pack and require quality gates to pass."""
        return self._engine.generate_strict(spec)

    def validate(self, pack: ToolPack) -> PackValidationReport:
        """Validate an existing pack against the standard layout."""
        return self._validator.validate(pack)

    def accept(self, pack: ToolPack) -> bool:
        """Return ``True`` when ``pack`` passes the quality gates.

        A pack is accepted only when validation has no errors and every
        quality-gate file exists.
        """
        report = pack.validation if pack.validation is not None else self._validator.validate(pack)
        if not report.passed:
            return False
        return all(pack.has(path) for path in quality_gate_files())

    def assert_acceptable(self, pack: ToolPack) -> ToolPack:
        """Raise :class:`PackValidationError` when ``pack`` fails the gates."""
        if not self.accept(pack):
            report = pack.validation if pack.validation is not None else self._validator.validate(pack)
            raise PackValidationError(
                f"tool integration pack '{pack.pack_id}' did not pass the quality gates.",
                issues=report.issues,
            )
        return pack

    # -- layout -------------------------------------------------------------

    def pack_layout(self) -> dict[str, str]:
        """Return the standard pack layout as ``path -> purpose``."""
        return {path: purpose for path, (_kind, purpose) in PACK_LAYOUT.items()}

    def required_files(self) -> list[str]:
        """Return every file a complete pack must contain."""
        return required_files()

    def quality_gates(self) -> list[str]:
        """Return the quality-gate files required for acceptance."""
        return quality_gate_files()

    # -- templates ----------------------------------------------------------

    def register_template(self, template: IntegrationTemplate) -> IntegrationTemplate:
        """Register an integration template override."""
        return self._templates.register(template)

    def list_templates(self) -> list[IntegrationTemplate]:
        """Return every known integration template."""
        return self._templates.list()

    def template(self, template_id: str) -> IntegrationTemplate:
        """Return a template by identifier (raising when unknown)."""
        return self._templates.get(template_id)

    # -- compatibility ------------------------------------------------------

    def compatibility_matrix(self, spec: ToolPackSpec) -> CompatibilityMatrix:
        """Build the compatibility matrix declared by ``spec``."""
        return self._compatibility.build_matrix(spec)

    def check_compatibility(
        self,
        spec: ToolPackSpec,
        *,
        hunterx_version: str | None = None,
    ) -> Result[bool, Exception]:
        """Check ``spec`` compatibility against a HunterX version."""
        return self._compatibility.check(spec, hunterx_version=hunterx_version)

    # -- persistence --------------------------------------------------------

    def save(self, pack: ToolPack) -> ToolPack:
        """Persist a pack through the pack repository."""
        if self._repository is None:
            raise ToolPackNotFoundError(pack.pack_id)
        self._repository.save(pack)
        return pack

    def get(self, pack_id: str) -> ToolPack | None:
        """Return a persisted pack, or ``None``."""
        if self._repository is None:
            return None
        return self._repository.get(pack_id)

    def list_packs(self, *, vendor: str | None = None) -> list[ToolPack]:
        """List persisted packs, optionally filtered by vendor."""
        if self._repository is None:
            return []
        return list(self._repository.list(vendor=vendor, limit=10_000))

    def delete(self, pack_id: str) -> None:
        """Delete a persisted pack."""
        if self._repository is None:
            raise ToolPackNotFoundError(pack_id)
        try:
            self._repository.delete(pack_id)
        except NotFoundError as exc:
            raise ToolPackNotFoundError(pack_id) from exc
