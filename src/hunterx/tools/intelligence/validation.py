# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool validation framework.

Validates configuration, installation, compatibility, dependencies and
permissions for registered tools. Produces structured validation reports so
broken tool registrations are detected early.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hunterx.domain.tool_intelligence import ToolMetadata
from hunterx.tools.intelligence.compatibility import CompatibilityEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry


class ValidationSeverity(Enum):
    """Severity of a validation finding."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True, slots=True)
class ValidationFinding:
    """A single validation finding.

    Attributes:
        severity: severity of the finding.
        check: which check produced it (e.g. ``configuration``).
        message: human-readable message.

    """

    severity: ValidationSeverity
    check: str
    message: str


@dataclass(slots=True)
class ValidationReport:
    """The outcome of validating a tool.

    Attributes:
        tool_id: the validated tool.
        findings: validation findings.
        valid: ``True`` when there are no ERROR findings.

    """

    tool_id: str
    findings: list[ValidationFinding] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Return ``True`` when no ERROR findings exist."""
        return not any(
            finding.severity == ValidationSeverity.ERROR for finding in self.findings
        )

    def errors(self) -> list[ValidationFinding]:
        """Return the ERROR findings."""
        return [f for f in self.findings if f.severity == ValidationSeverity.ERROR]


class ToolValidationFramework:
    """Validate every facet of a tool registration.

    Checks: configuration (metadata completeness), installation (runtime
    state), compatibility (declared profile), dependencies (capability
    requirements satisfiable) and permissions.
    """

    def __init__(
        self,
        registry: ToolIntelligenceRegistry,
        compatibility: CompatibilityEngine,
    ) -> None:
        self._registry = registry
        self._compatibility = compatibility

    def validate(
        self,
        tool_id: str,
        *,
        os_name: str = "",
        architecture: str = "",
        docker: bool = False,
        air_gapped: bool = False,
        cloud: bool = False,
    ) -> ValidationReport:
        """Run all checks for ``tool_id`` and return a report."""
        report = ValidationReport(tool_id=tool_id)
        metadata = self._registry.get_metadata(tool_id)
        if metadata is None:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.ERROR, "configuration", "tool is not registered"
                )
            )
            return report

        self._check_configuration(metadata, report)
        self._check_installation(tool_id, report)
        self._check_compatibility(
            tool_id, report, os_name=os_name, architecture=architecture,
            docker=docker, air_gapped=air_gapped, cloud=cloud,
        )
        self._check_dependencies(tool_id, report)
        self._check_permissions(metadata, report)
        return report

    def _check_configuration(self, metadata: ToolMetadata, report: ValidationReport) -> None:
        if not metadata.display_name:
            report.findings.append(
                ValidationFinding(ValidationSeverity.WARNING, "configuration", "missing display name")
            )
        if not metadata.category:
            report.findings.append(
                ValidationFinding(ValidationSeverity.WARNING, "configuration", "missing category")
            )
        if not metadata.version:
            report.findings.append(
                ValidationFinding(ValidationSeverity.WARNING, "configuration", "missing version")
            )
        if metadata.execution_type is None:
            report.findings.append(
                ValidationFinding(ValidationSeverity.ERROR, "configuration", "missing execution type")
            )

    def _check_installation(self, tool_id: str, report: ValidationReport) -> None:
        from hunterx.domain.tool_intelligence import ToolState

        state = self._registry.get_state(tool_id)
        if state is None:
            report.findings.append(
                ValidationFinding(ValidationSeverity.ERROR, "installation", "no runtime state")
            )
            return
        if state.state == ToolState.REGISTERED:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.WARNING, "installation", "tool is registered but not installed"
                )
            )
        if not state.installed_version and state.state not in (
            ToolState.REGISTERED,
            ToolState.DISABLED,
        ):
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.WARNING, "installation", "installed version unknown"
                )
            )

    def _check_compatibility(
        self,
        tool_id: str,
        report: ValidationReport,
        *,
        os_name: str,
        architecture: str,
        docker: bool,
        air_gapped: bool,
        cloud: bool,
    ) -> None:
        profile = self._registry.get_compatibility(tool_id)
        if profile is None:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.WARNING, "compatibility", "no compatibility profile"
                )
            )
            return
        result = self._compatibility.check(
            tool_id,
            os_name=os_name,
            architecture=architecture,
            docker=docker,
            air_gapped=air_gapped,
            cloud=cloud,
        )
        if not result.compatible:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.ERROR,
                    "compatibility",
                    "not compatible: " + ", ".join(result.missing),
                )
            )
        if profile.python_versions and not profile.docker:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.INFO,
                    "compatibility",
                    f"python versions: {', '.join(profile.python_versions)}",
                )
            )

    def _check_dependencies(self, tool_id: str, report: ValidationReport) -> None:
        knowledge = self._registry.get_knowledge(tool_id)
        if knowledge is None:
            return
        for dependency in knowledge.dependencies:
            providers = self._registry.providers_for(dependency.capability)
            if not providers:
                severity = (
                    ValidationSeverity.WARNING if dependency.optional else ValidationSeverity.ERROR
                )
                report.findings.append(
                    ValidationFinding(
                        severity,
                        "dependencies",
                        f"capability '{dependency.capability}' has no provider",
                    )
                )

    def _check_permissions(self, metadata: ToolMetadata, report: ValidationReport) -> None:
        if not metadata.tags and not metadata.license:
            report.findings.append(
                ValidationFinding(
                    ValidationSeverity.WARNING, "permissions", "license not declared"
                )
            )

    def validate_mapping(self, raw: dict[str, Any]) -> ValidationReport:
        """Validate a raw metadata mapping before registration.

        Performs lightweight structural checks; does not require an existing
        registration.
        """
        tool_id = str(raw.get("tool_id", ""))
        report = ValidationReport(tool_id=tool_id)
        if not tool_id:
            report.findings.append(
                ValidationFinding(ValidationSeverity.ERROR, "configuration", "missing tool_id")
            )
        return report
