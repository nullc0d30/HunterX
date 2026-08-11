# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Report template engine.

Data-driven report templates: the template defines its sections in data and
the engine returns the ordered section list for a template kind. Report
structure is never hardcoded into business logic.
"""

from __future__ import annotations

from hunterx.domain.reporting.enums import TemplateKind
from hunterx.domain.reporting.models import ReportTemplate, TemplateSection
from hunterx.shared.ids import generate_id

#: Ordered sections per template kind.
_SECTIONS: dict[TemplateKind, tuple[tuple[str, str], ...]] = {
    TemplateKind.BUG_BOUNTY: (
        ("title", "Title"),
        ("summary", "Summary"),
        ("affected_asset", "Affected Asset"),
        ("affected_endpoint", "Affected Endpoint"),
        ("parameter", "Parameter"),
        ("severity", "Severity"),
        ("impact", "Impact"),
        ("technical_description", "Technical Description"),
        ("steps_to_reproduce", "Steps to Reproduce"),
        ("poc", "PoC"),
        ("evidence", "Evidence"),
        ("expected_result", "Expected Result"),
        ("actual_result", "Actual Result"),
        ("business_impact", "Business Impact"),
        ("remediation", "Remediation"),
        ("references", "References"),
        ("timeline", "Timeline"),
        ("confidence", "Confidence"),
        ("provenance", "Provenance"),
    ),
    TemplateKind.PENTEST: (
        ("executive_summary", "Executive Summary"),
        ("scope", "Scope"),
        ("methodology", "Methodology"),
        ("attack_surface", "Attack Surface"),
        ("findings_summary", "Findings Summary"),
        ("detailed_findings", "Detailed Findings"),
        ("risk_rating", "Risk Rating"),
        ("evidence", "Evidence"),
        ("attack_paths", "Attack Paths"),
        ("root_causes", "Root Causes"),
        ("remediation", "Remediation"),
        ("retest_plan", "Retest Plan"),
        ("appendices", "Appendices"),
        ("tooling", "Tooling / Methodology"),
    ),
    TemplateKind.EXECUTIVE_PENTEST: (
        ("executive_summary", "Executive Summary"),
        ("findings_summary", "Findings Summary"),
        ("critical_assets", "Critical Assets"),
        ("major_attack_paths", "Major Attack Paths"),
        ("root_causes", "Root Causes"),
        ("risk_concentration", "Risk Concentration"),
        ("remediation_priorities", "Remediation Priorities"),
        ("validated_impact", "Validated Impact"),
    ),
    TemplateKind.TECHNICAL_PENTEST: (
        ("scope", "Scope"),
        ("methodology", "Methodology"),
        ("detailed_findings", "Detailed Findings"),
        ("evidence", "Evidence"),
        ("attack_paths", "Attack Paths"),
        ("root_causes", "Root Causes"),
        ("remediation", "Remediation"),
        ("retest_plan", "Retest Plan"),
        ("appendices", "Appendices"),
        ("tooling", "Tooling / Methodology"),
    ),
    TemplateKind.WEB_APP_PENTEST: (
        ("executive_summary", "Executive Summary"),
        ("scope", "Scope"),
        ("methodology", "Methodology"),
        ("attack_surface", "Attack Surface"),
        ("findings_summary", "Findings Summary"),
        ("detailed_findings", "Detailed Findings"),
        ("evidence", "Evidence"),
        ("reproduction", "Reproduction"),
        ("remediation", "Remediation"),
        ("retest_plan", "Retest Plan"),
        ("appendices", "Appendices"),
    ),
    TemplateKind.API_PENTEST: (
        ("executive_summary", "Executive Summary"),
        ("scope", "Scope"),
        ("api_surface", "API Surface"),
        ("methodology", "Methodology"),
        ("findings_summary", "Findings Summary"),
        ("detailed_findings", "Detailed Findings"),
        ("evidence", "Evidence"),
        ("remediation", "Remediation"),
        ("retest_plan", "Retest Plan"),
        ("appendices", "Appendices"),
    ),
    TemplateKind.CLOUD_ASSESSMENT: (
        ("executive_summary", "Executive Summary"),
        ("provider", "Provider"),
        ("account", "Account"),
        ("region", "Region"),
        ("resource", "Resource"),
        ("exposure", "Exposure"),
        ("identity", "Identity"),
        ("configuration", "Configuration"),
        ("network_relationship", "Network Relationship"),
        ("attack_path", "Attack Path"),
        ("evidence", "Evidence"),
        ("impact", "Impact"),
        ("remediation", "Remediation"),
    ),
    TemplateKind.RED_TEAM: (
        ("objective", "Objective"),
        ("scope", "Scope"),
        ("attack_narrative", "Attack Narrative"),
        ("initial_access", "Initial Access"),
        ("discovery", "Discovery"),
        ("credential_access", "Credential Access"),
        ("privilege_escalation", "Privilege Escalation"),
        ("lateral_movement", "Lateral Movement"),
        ("persistence", "Persistence"),
        ("objectives", "Objectives"),
        ("detection_observations", "Detection Observations"),
        ("attack_path", "Attack Path"),
        ("evidence", "Evidence"),
        ("impact", "Impact"),
        ("defensive_recommendations", "Defensive Recommendations"),
    ),
    TemplateKind.VULNERABILITY_DISCLOSURE: (
        ("title", "Title"),
        ("summary", "Summary"),
        ("affected_asset", "Affected Asset"),
        ("severity", "Severity"),
        ("impact", "Impact"),
        ("technical_description", "Technical Description"),
        ("steps_to_reproduce", "Steps to Reproduce"),
        ("evidence", "Evidence"),
        ("remediation", "Remediation"),
        ("timeline", "Timeline"),
        ("disclosure_contact", "Disclosure Contact"),
    ),
    TemplateKind.RESEARCH: (
        ("title", "Title"),
        ("summary", "Summary"),
        ("technical_description", "Technical Description"),
        ("methodology", "Methodology"),
        ("evidence", "Evidence"),
        ("impact", "Impact"),
        ("remediation", "Remediation"),
        ("references", "References"),
    ),
}


class ReportTemplateEngine:
    """Data-driven template provider."""

    def __init__(self, schema_version: str = "1.0.0") -> None:
        self._schema_version = schema_version

    def template_for(self, kind: TemplateKind, *, version: str = "1.0.0", locale: str = "en") -> ReportTemplate:
        """Return the template for ``kind``.

        Args:
            kind: template kind.
            version: template version.
            locale: template locale.

        Returns:
            A data-driven :class:`ReportTemplate`.

        """
        section_keys = _SECTIONS.get(kind, _SECTIONS[TemplateKind.PENTEST])
        sections = tuple(
            TemplateSection(
                key=key,
                title=title,
                order=index,
                required=index < 5,
                description=f"Section '{title}' for template {kind.value}",
            )
            for index, (key, title) in enumerate(section_keys)
        )
        return ReportTemplate(
            template_id=generate_id(),
            kind=kind,
            version=version,
            title=kind.value.replace("_", " ").title(),
            sections=sections,
            schema_version=self._schema_version,
            locale=locale,
        )

    def list_kinds(self) -> tuple[TemplateKind, ...]:
        """Return every supported template kind."""
        return tuple(TemplateKind)


__all__ = ["ReportTemplateEngine"]
