# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Cloud & SaaS Intelligence.

Registers the cloud analysis tool (in-process analyzer) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
it by taxonomy capability (``cloud-intelligence``,
``cloud-attack-surface-intelligence``). The profile mirrors the tool descriptor
used by the Tool Integration SDK adapter (same version pin) so intelligence and
execution never disagree about a tool's contract.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolDependency,
    ToolExecutionMode,
    ToolExecutionType,
    ToolInputContract,
    ToolKnowledge,
    ToolMetadata,
    ToolOutputContract,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Shared mission profiles that exercise the cloud intelligence capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the cloud tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared cloud intelligence capability identifiers.
_CAPABILITIES = ("cloud-intelligence", "saas-intelligence", "cloud-attack-surface-intelligence")


@dataclass(frozen=True, slots=True)
class CloudToolSpec:
    """A single cloud tool profile for TIP registration."""

    tool_id: str
    display_name: str
    vendor: str
    project_url: str
    license: str
    subcategory: str
    version: str
    language: str
    description: str
    capabilities: tuple[str, ...]
    tags: tuple[str, ...]
    accepts: tuple[str, ...] = ("url", "host", "domain", "http-snapshot", "script", "document")
    required_inputs: tuple[str, ...] = ("cloud_input",)
    formats: tuple[str, ...] = ("json",)
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_CLOUD_TOOLS: tuple[CloudToolSpec, ...] = (
    CloudToolSpec(
        tool_id="cloud-analysis",
        display_name="Cloud & SaaS Attack-Surface Analyzer",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="cloud",
        version="1.0.0",
        language="python",
        description=(
            "In-process cloud & SaaS attack-surface intelligence: cloud "
            "providers, accounts/subscriptions/projects, regions, resources, "
            "services, endpoints (control/data/identity/management plane), "
            "environments, identity & IAM indicators, SaaS platforms and "
            "integrations, webhooks, third-party dependencies and "
            "storage/compute/container/Kubernetes/database/CI-CD resource "
            "indicators from static material. Intelligence & discovery only; "
            "never authenticates, never accesses cloud resources and never "
            "retrieves secrets."
        ),
        capabilities=_CAPABILITIES,
        tags=("cloud", "saas", "attack-surface", "in-process", "intelligence"),
        accepts=("url", "host", "domain", "http-snapshot", "script", "document"),
        required_inputs=("cloud_input",),
        formats=("json",),
        arguments=(
            ToolArgument(
                "cloud_input", "", "object", description="Static cloud input bundle (DNS, TLS, headers, scripts, docs)."
            ),
        ),
        modes=(
            ToolExecutionMode(
                "passive", description="Analyse supplied static material only; no acquisition.", safe=True
            ),
            ToolExecutionMode(
                "active", description="Analyse acquired material with the full detector set.", aggressive=False
            ),
        ),
        limitations=(
            "Static analysis only; never authenticates, never accesses cloud resources.",
            "Sensitive values are masked or fingerprinted before persistence.",
            "Cloud exposure indicators are intelligence, never vulnerabilities.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=(),
    ),
)


def register_cloud_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated cloud tool into ``tip`` (REGISTERED state)."""
    for spec in _CLOUD_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def cloud_tool_specs() -> tuple[CloudToolSpec, ...]:
    """Return the cloud tool profiles registered by :func:`register_cloud_tools`."""
    return _CLOUD_TOOLS


def _metadata(spec: CloudToolSpec) -> ToolMetadata:
    return ToolMetadata(
        tool_id=spec.tool_id,
        display_name=spec.display_name,
        vendor=spec.vendor,
        project_url=spec.project_url,
        license=spec.license,
        category="recon",
        subcategory=spec.subcategory,
        version=spec.version,
        platforms=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        language=spec.language,
        execution_type=ToolExecutionType.PIP,
        package_manager="pip",
        container_available=True,
        binary_available=False,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=75.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: CloudToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=(
                "domain",
                "records",
                "certificates",
                "headers",
                "html",
                "scripts",
                "api_schemes",
                "documents",
                "technologies",
                "observed_urls",
            ),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="cloud-observations",
            normalizer="cloud-normalizer",
            event_types=(
                "cloud.intelligence.started",
                "cloud.provider.discovered",
                "cloud.resource.discovered",
                "cloud.saas.discovered",
                "cloud.intelligence.completed",
            ),
            evidence_capture=("cloud", "evidence"),
        ),
        cli_binary="",
        cli_structure="library",
        arguments=spec.arguments,
        modes=spec.modes or (ToolExecutionMode("passive", description="Analyse supplied static material.", safe=True),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(ToolDependency(capability="python", description="Cloud analysis runs in-process"),),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Analyse in-scope static material only, through configured scope.",),
        common_mistakes=(
            "Attempting to authenticate to cloud accounts or retrieve cloud secrets.",
            "Treating exposure indicators as validated vulnerabilities.",
        ),
        examples=(f"{spec.tool_id} url=https://example.com",),
        references=(),
    )


def _compatibility(spec: CloudToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=True,
        cloud=True,
        air_gapped=False,
    )
