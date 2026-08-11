# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Authentication Intelligence.

Registers the authentication analysis tool (in-process analyzer) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
it by taxonomy capability (``authentication-intelligence``,
``identity-intelligence``). The profile mirrors the tool descriptor used by the
Tool Integration SDK adapter (same version pin) so intelligence and execution
never disagree about a tool's contract.
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

#: Shared mission profiles that exercise the authentication capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the auth tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared authentication intelligence capability identifiers.
_CAPABILITIES = ("authentication-intelligence", "identity-intelligence", "session-intelligence")


@dataclass(frozen=True, slots=True)
class AuthToolSpec:
    """A single auth tool profile for TIP registration."""

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
    required_inputs: tuple[str, ...] = ("auth_input",)
    formats: tuple[str, ...] = ("json",)
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_AUTH_TOOLS: tuple[AuthToolSpec, ...] = (
    AuthToolSpec(
        tool_id="auth-analysis",
        display_name="Authentication Analyzer",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="web",
        version="1.0.0",
        language="python",
        description=(
            "In-process authentication, session & identity intelligence: "
            "authentication surfaces, endpoints, modeled flows, identity "
            "providers, OAuth/OIDC/SAML configurations, JWT indicators, cookie "
            "security metadata, token storage, CSRF, CORS, MFA/WebAuthn and "
            "role/scope/tenant indicators from static material. Intelligence "
            "only; never authenticates or validates discovered tokens."
        ),
        capabilities=_CAPABILITIES,
        tags=("authentication", "identity", "session", "in-process", "intelligence"),
        accepts=("url", "host", "domain", "http-snapshot", "script"),
        required_inputs=("auth_input",),
        formats=("json",),
        arguments=(
            ToolArgument("auth_input", "", "object", description="Static input bundle (HTTP snapshot, scripts, schemes)."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Analyse supplied static material only; no acquisition.", safe=True),
            ToolExecutionMode("active", description="Analyse acquired material with the full detector set.", aggressive=False),
        ),
        limitations=(
            "Static analysis only; never authenticates, never validates tokens.",
            "Sensitive values are masked before persistence.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=(),
    ),
)


def register_auth_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated authentication tool into ``tip`` (REGISTERED state)."""
    for spec in _AUTH_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def auth_tool_specs() -> tuple[AuthToolSpec, ...]:
    """Return the authentication tool profiles registered by :func:`register_auth_tools`."""
    return _AUTH_TOOLS


def _metadata(spec: AuthToolSpec) -> ToolMetadata:
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


def _knowledge(spec: AuthToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("url", "status_code", "headers", "cookies", "html", "scripts", "api_schemes", "documents"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="auth-observations",
            normalizer="auth-normalizer",
            event_types=(
                "auth.discovery.started",
                "auth.login_surface.discovered",
                "auth.endpoint.discovered",
                "auth.discovery.completed",
            ),
            evidence_capture=("auth", "evidence"),
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
            ToolDependency(capability="python", description="Authentication analysis runs in-process"),
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Analyse in-scope static material only, through configured scope.",),
        common_mistakes=(
            "Attempting to authenticate with discovered credentials or validating discovered tokens.",
        ),
        examples=(f"{spec.tool_id} url=https://example.com/login",),
        references=(),
    )


def _compatibility(spec: AuthToolSpec) -> ToolCompatibility:
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
