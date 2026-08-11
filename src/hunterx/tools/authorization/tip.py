# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Authorization Intelligence.

Registers the authorization analysis tool (in-process analyzer) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
it by taxonomy capability (``authorization-intelligence``,
``access-control-intelligence``). The profile mirrors the tool descriptor used
by the Tool Integration SDK adapter (same version pin) so intelligence and
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

#: Shared mission profiles that exercise the authorization capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the authorization tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared authorization intelligence capability identifiers.
_CAPABILITIES = ("authorization-intelligence", "access-control-intelligence", "permission-intelligence")


@dataclass(frozen=True, slots=True)
class AuthorizationToolSpec:
    """A single authorization tool profile for TIP registration."""

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
    accepts: tuple[str, ...] = ("url", "host", "domain")
    required_inputs: tuple[str, ...] = ("authorization_input",)
    formats: tuple[str, ...] = ("json",)
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_AUTHORIZATION_TOOLS: tuple[AuthorizationToolSpec, ...] = (
    AuthorizationToolSpec(
        tool_id="authorization-analysis",
        display_name="Authorization Analyzer",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="web",
        version="1.0.0",
        language="python",
        description=(
            "In-process authorization & access-control intelligence: subjects, "
            "roles, groups, permissions, scopes, claims, policies, resources, "
            "actions, ownership, tenancy, admin surfaces, function/object/"
            "field-level access control, frontend/backend enforcement, API/"
            "GraphQL/WebSocket/service authorization and decision indicators "
            "from static material. Intelligence only; never tests authorization."
        ),
        capabilities=_CAPABILITIES,
        tags=("authorization", "access-control", "rbac", "abac", "in-process", "intelligence"),
        accepts=("url", "host", "domain", "http-snapshot", "script"),
        required_inputs=("authorization_input",),
        formats=("json",),
        arguments=(
            ToolArgument(
                "authorization_input",
                "",
                "object",
                description="Static input bundle (HTTP snapshot, scripts, operations).",
            ),
        ),
        modes=(
            ToolExecutionMode(
                "passive",
                description="Analyse supplied static material only; no acquisition, no authorization testing.",
                safe=True,
            ),
            ToolExecutionMode(
                "active",
                description="Analyse acquired material with the full detector set.",
                aggressive=False,
            ),
        ),
        limitations=(
            "Static analysis only; never tests authorization behaviour.",
            "Sensitive values and identifiers are masked before persistence.",
            "Frontend checks are recorded as indicators, never as backend enforcement.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=(),
    ),
)


def register_authorization_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated authorization tool into ``tip`` (REGISTERED state)."""
    for spec in _AUTHORIZATION_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def authorization_tool_specs() -> tuple[AuthorizationToolSpec, ...]:
    """Return the authorization tool profiles registered by :func:`register_authorization_tools`."""
    return _AUTHORIZATION_TOOLS


def _metadata(spec: AuthorizationToolSpec) -> ToolMetadata:
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


def _knowledge(spec: AuthorizationToolSpec) -> ToolKnowledge:
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
                "url",
                "status_code",
                "headers",
                "html",
                "scripts",
                "api_schemes",
                "api_operations",
                "graphql",
                "websockets",
                "documents",
            ),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="authorization-observations",
            normalizer="authorization-normalizer",
            event_types=(
                "authorization.discovery.started",
                "authorization.resource.discovered",
                "authorization.admin_surface.discovered",
                "authorization.discovery.completed",
            ),
            evidence_capture=("authorization", "evidence"),
        ),
        cli_binary="",
        cli_structure="library",
        arguments=spec.arguments,
        modes=spec.modes
        or (ToolExecutionMode("passive", description="Analyse supplied static material.", safe=True),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(
            ToolDependency(capability="python", description="Authorization analysis runs in-process"),
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Analyse in-scope static material only, through configured scope.",),
        common_mistakes=(
            "Testing authorization behaviour, swapping identifiers or accessing other users'/tenants' resources.",
        ),
        examples=(f"{spec.tool_id} url=https://example.com/api",),
        references=(),
    )


def _compatibility(spec: AuthorizationToolSpec) -> ToolCompatibility:
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
