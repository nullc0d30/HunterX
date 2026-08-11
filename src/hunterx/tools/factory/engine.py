# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Integration Factory generator engine.

Runs every pack generator in a fixed order, renders integration templates,
assembles the resulting files into a :class:`ToolPack`, validates it and
persists it through a :class:`ToolPackRepository`. All pack generation funnels
through this engine so every pack follows identical engineering standards.
"""

from __future__ import annotations

from hunterx.domain.exceptions import (
    GeneratorNotFoundError,
    PackGenerationError,
    PackValidationError,
)
from hunterx.domain.ports.tool_factory import ToolPackRepository
from hunterx.domain.tool_factory import (
    GeneratedFile,
    PackArtifactKind,
    PackValidationReport,
    ToolPack,
    ToolPackManifest,
    ToolPackSpec,
    manifest_to_yaml,
)
from hunterx.shared.result import Failure, Result, Success
from hunterx.tools.factory.compatibility import CompatibilityValidator
from hunterx.tools.factory.generators import PackContext, PackGenerator, default_generators
from hunterx.tools.factory.layout import GENERATOR_VERSION, PACK_STRUCTURE_VERSION
from hunterx.tools.factory.render import TemplateRenderer, render_context
from hunterx.tools.factory.templates import PackTemplateStore
from hunterx.tools.factory.validator import ToolPackValidator


class ToolPackGeneratorEngine:
    """Composition root that generates Tool Integration Packs."""

    generator_version = GENERATOR_VERSION

    def __init__(
        self,
        *,
        templates: PackTemplateStore | None = None,
        renderer: TemplateRenderer | None = None,
        validator: ToolPackValidator | None = None,
        compatibility: CompatibilityValidator | None = None,
        repository: ToolPackRepository | None = None,
        generators: list[PackGenerator] | None = None,
    ) -> None:
        self._templates = templates or PackTemplateStore()
        self._renderer = renderer or TemplateRenderer()
        self._validator = validator or ToolPackValidator()
        self._compatibility = compatibility or CompatibilityValidator()
        self._generators = list(generators) if generators is not None else default_generators()
        self._repository = repository

    # -- generators ---------------------------------------------------------

    def generator(self, name: str) -> PackGenerator:
        """Return a generator by name, raising :class:`GeneratorNotFoundError`."""
        for generator in self._generators:
            if generator.name == name:
                return generator
        raise GeneratorNotFoundError(name)

    def generator_names(self) -> list[str]:
        """Return every registered generator name in execution order."""
        return [generator.name for generator in self._generators]

    # -- generation ---------------------------------------------------------

    def generate(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a pack for ``spec``, returning a :class:`Result`.

        Structural failures (invalid spec, render errors, duplicate files)
        produce a :class:`Failure`; validation issues are attached to the
        pack's report and never prevent generation.
        """
        try:
            return Success(self.generate_pack(spec))
        except (PackGenerationError, PackValidationError) as exc:
            return Failure(exc)

    def generate_pack(self, spec: ToolPackSpec) -> ToolPack:
        """Generate and validate a pack, raising on structural failure."""
        if not isinstance(spec, ToolPackSpec):
            raise PackGenerationError("a ToolPackSpec is required to generate a pack.")
        template_files = self._templates.resolve(spec.template_id)
        context = PackContext(
            spec=spec,
            templates=template_files,
            renderer=self._renderer,
            context=render_context(spec),
        )
        files: list[GeneratedFile] = []
        for generator in self._generators:
            files.extend(generator.generate(context))
        files.sort(key=lambda file: file.path)
        report = PackValidationReport(spec.pack_id)
        manifest = self._build_manifest(spec, files, report)
        manifest_file = GeneratedFile(
            path="pack.yaml",
            content=manifest_to_yaml(manifest) + "\n",
            kind=PackArtifactKind.MANIFEST,
        )
        files.append(manifest_file)
        files.sort(key=lambda file: file.path)
        provisional = ToolPack(
            pack_id=spec.pack_id,
            vendor=spec.vendor,
            name=str(context.context["display_name"]),
            version=spec.version,
            files=tuple(files),
            manifest=manifest,
        )
        report = self._validator.validate(provisional)
        manifest = self._build_manifest(spec, files, report)
        files = [
            GeneratedFile(
                path=file.path,
                content=manifest_to_yaml(manifest) + "\n" if file.path == "pack.yaml" else file.content,
                kind=file.kind,
            )
            for file in files
        ]
        pack = ToolPack(
            pack_id=spec.pack_id,
            vendor=spec.vendor,
            name=str(context.context["display_name"]),
            version=spec.version,
            files=tuple(files),
            manifest=manifest,
            validation=report,
        )
        if self._repository is not None:
            self._repository.save(pack)
        return pack

    def generate_strict(self, spec: ToolPackSpec) -> Result[ToolPack, Exception]:
        """Generate a pack and require quality gates to pass.

        Returns a :class:`Failure` carrying :class:`PackValidationError` when
        the generated pack fails validation.
        """
        result = self.generate(spec)
        if isinstance(result, Failure):
            return result
        pack = result.value
        if pack.validation is None or not pack.validation.passed:
            issues = pack.validation.issues if pack.validation is not None else []
            return Failure(
                PackValidationError(
                    f"generated pack '{spec.pack_id}' failed validation.",
                    issues=issues,
                )
            )
        return Success(pack)

    def validate(self, pack: ToolPack) -> PackValidationReport:
        """Validate an existing pack."""
        return self._validator.validate(pack)

    def compatibility_matrix(self, spec: ToolPackSpec) -> object:
        """Build the compatibility matrix for ``spec``."""
        return self._compatibility.build_matrix(spec)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _build_manifest(
        spec: ToolPackSpec,
        files: list[GeneratedFile],
        report: PackValidationReport,
    ) -> ToolPackManifest:
        return ToolPackManifest(
            pack_id=spec.pack_id,
            vendor=spec.vendor,
            name=spec.display_name or " ".join(part.capitalize() for part in spec.tool_name.split("-")),
            version=spec.version,
            description=spec.description,
            author=spec.author,
            license=spec.license,
            entrypoint=spec.entrypoint,
            structure_version=PACK_STRUCTURE_VERSION,
            generator_version=GENERATOR_VERSION,
            capabilities=spec.capabilities,
            targets=spec.targets,
            files=tuple(file.path for file in files),
            quality_gates_passed=report.passed,
            validation=report.to_dict(),
        )
