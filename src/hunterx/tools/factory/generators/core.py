# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Core generators: metadata, versioning, knowledge and installation.

Emits the structured configuration of a Tool Integration Pack: tool metadata,
the semantic version definition plus compatibility matrix and migration
notes, the knowledge profile and capabilities, and the installation /
dependency / health-check definitions.
"""

from __future__ import annotations

from hunterx.domain.tool_factory import (
    CompatibilityEntry,
    CompatibilityMatrix,
    PackArtifactKind,
    SemanticVersion,
    render_yaml,
)
from hunterx.tools.factory.generators.base import PackContext, PackGenerator
from hunterx.tools.factory.layout import HUNTERX_VERSION


class MetadataGenerator(PackGenerator):
    """Generates the tool metadata record (``metadata/tool.yaml``)."""

    name = "metadata"
    description = "Generates the tool metadata record."

    def generate(self, ctx: PackContext):
        """Emit the tool metadata file."""
        spec = ctx.spec
        data = {
            "tool_id": spec.pack_id,
            "display_name": ctx.context["display_name"],
            "vendor": spec.vendor,
            "version": spec.version,
            "description": spec.description,
            "execution_type": spec.execution_type.value,
            "package_manager": spec.package_manager,
            "cli_binary": spec.cli_binary or spec.tool_name,
            "platforms": list(spec.platforms),
            "architectures": list(spec.architectures),
            "tags": ["security", spec.pack_id],
        }
        content = render_yaml(data) + "\n"
        return [self.file("metadata/tool.yaml", content, PackArtifactKind.METADATA)]


class VersionMetadataGenerator(PackGenerator):
    """Generates the version definition, compatibility matrix and migrations."""

    name = "version-metadata"
    description = "Generates version definition, compatibility matrix and migration notes."

    def generate(self, ctx: PackContext):
        """Emit version, compatibility and migration records."""
        spec = ctx.spec
        version = SemanticVersion.parse(spec.version)
        entries = [
            CompatibilityEntry(
                tool_version=spec.version,
                hunterx_version=target,
                status="deprecated" if spec.deprecated else "compatible",
                notes=spec.deprecation_reason if spec.deprecated else "",
            )
            for target in (spec.hunterx_versions or (HUNTERX_VERSION,))
        ]
        matrix = CompatibilityMatrix(spec.pack_id, tuple(entries))
        version_data = {
            "tool_id": spec.pack_id,
            "semver": spec.version,
            "major": version.major,
            "minor": version.minor,
            "patch": version.patch,
            "prerelease": version.prerelease,
            "build": version.build,
            "compatibility_rule": "same-major" if version.major >= 1 else "same-minor",
            "deprecation": {
                "deprecated": spec.deprecated,
                "reason": spec.deprecation_reason,
            },
        }
        compatibility_data = {
            "tool_id": spec.pack_id,
            "entries": [entry.to_dict() for entry in matrix.entries],
        }
        migrations_data = {
            "tool_id": spec.pack_id,
            "migrations": [],
            "policy": {
                "semver": "major.minor.patch",
                "deprecation_policy": (
                    "declared deprecated; replaced or removed on the next major release"
                    if spec.deprecated
                    else "backwards-compatible within the compatibility rule"
                ),
                "migration_support": "backwards-compatible within the declared compatibility rule",
            },
        }
        return [
            self.file("metadata/version.yaml", render_yaml(version_data) + "\n", PackArtifactKind.VERSION),
            self.file(
                "metadata/compatibility.yaml",
                render_yaml(compatibility_data) + "\n",
                PackArtifactKind.COMPATIBILITY,
            ),
            self.file(
                "metadata/migrations.yaml",
                render_yaml(migrations_data) + "\n",
                PackArtifactKind.MIGRATIONS,
            ),
        ]


class KnowledgeFileGenerator(PackGenerator):
    """Generates the knowledge profile and capabilities files."""

    name = "knowledge"
    description = "Generates the knowledge profile and capabilities records."

    def generate(self, ctx: PackContext):
        """Emit the knowledge profile and capabilities records."""
        spec = ctx.spec
        capabilities = [
            {
                "capability_id": capability,
                "name": _capability_name(capability),
                "category": _capability_category(capability),
                "subcategory": _capability_subcategory(capability),
                "description": f"Provides {capability} capability.",
                "missions": list(spec.mission_profiles),
            }
            for capability in spec.capabilities
        ]
        knowledge_data = {
            "tool_id": spec.pack_id,
            "purpose": spec.description or f"Runs {spec.tool_name}.",
            "capabilities": list(spec.capabilities),
            "supported_assessments": [],
            "supported_mission_profiles": list(spec.mission_profiles),
            "inputs": {
                "accepts": list(spec.targets),
                "required": [],
                "optional": list(spec.parameters.keys()),
                "transforms": [],
                "max_targets_per_invocation": 1,
            },
            "outputs": {
                "formats": [spec.output_format],
                "parser": "parsing/parser.py",
                "normalizer": "parsing/normalizer.py",
                "event_types": [],
                "evidence_capture": ["file"],
                "dedup_key_spec": ["target", "title"],
            },
            "cli_binary": spec.cli_binary or spec.tool_name,
            "safe_mode": True,
            "aggressive_mode": False,
            "authentication_requirements": "none",
            "privileges_required": "none",
            "limitations": [],
            "known_issues": [],
            "dependencies": [],
            "examples": [],
            "references": [],
        }
        return [
            self.file(
                "knowledge/knowledge_profile.yaml",
                render_yaml(knowledge_data) + "\n",
                PackArtifactKind.KNOWLEDGE,
            ),
            self.file(
                "knowledge/capabilities.yaml",
                render_yaml({"capabilities": capabilities}) + "\n",
                PackArtifactKind.CAPABILITIES,
            ),
        ]


class InstallationGenerator(PackGenerator):
    """Generates installation, dependency and health-check definitions."""

    name = "installation"
    description = "Generates installation, dependency and health-check definitions."

    def generate(self, ctx: PackContext):
        """Emit installation, dependency and health-check records."""
        spec = ctx.spec
        installation_data = {
            "tool_id": spec.pack_id,
            "execution_type": spec.execution_type.value,
            "package_manager": spec.package_manager,
            "install_command": spec.install_command,
            "binary": spec.cli_binary or spec.tool_name,
            "verified_versions": [spec.version],
        }
        dependencies_data = {
            "tool_id": spec.pack_id,
            "dependencies": [],
            "required_system": {},
        }
        health_data = {
            "tool_id": spec.pack_id,
            "command": spec.health_command or f"{spec.cli_binary or spec.tool_name} --version",
            "expected_exit_code": 0,
            "probes": [],
        }
        return [
            self.file(
                "install/installation.yaml",
                render_yaml(installation_data) + "\n",
                PackArtifactKind.INSTALLATION,
            ),
            self.file(
                "install/dependencies.yaml",
                render_yaml(dependencies_data) + "\n",
                PackArtifactKind.DEPENDENCY,
            ),
            self.file(
                "install/health_check.yaml",
                render_yaml(health_data) + "\n",
                PackArtifactKind.HEALTH,
            ),
        ]


def _capability_name(capability_id: str) -> str:
    return " ".join(part.capitalize() for part in capability_id.split("-"))


def _capability_category(capability_id: str) -> str:
    from hunterx.tools.intelligence.taxonomy import ToolTaxonomy

    category, _ = ToolTaxonomy().classify(capability_id)
    return category or "assessment"


def _capability_subcategory(capability_id: str) -> str:
    from hunterx.tools.intelligence.taxonomy import ToolTaxonomy

    _, subcategory = ToolTaxonomy().classify(capability_id)
    return subcategory or "general"
