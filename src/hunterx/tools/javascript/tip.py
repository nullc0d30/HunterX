# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for JavaScript Intelligence.

Registers the JavaScript analysis tool (in-process analyzer) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
it by taxonomy capability (``javascript-analysis``, ``client-side-discovery``,
``secret-scanning``). The profile mirrors the tool descriptor used by the Tool
Integration SDK adapter (same version pin) so intelligence and execution never
disagree about a tool's contract.
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

#: Shared mission profiles that exercise the JavaScript capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the JavaScript tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared JavaScript intelligence capability identifiers.
_CAPABILITIES = ("javascript-analysis", "client-side-discovery", "secret-scanning")


@dataclass(frozen=True, slots=True)
class JavaScriptToolSpec:
    """A single JavaScript tool profile for TIP registration."""

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
    required_inputs: tuple[str, ...] = ("content", "url")
    formats: tuple[str, ...] = ("json",)
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_JAVASCRIPT_TOOLS: tuple[JavaScriptToolSpec, ...] = (
    JavaScriptToolSpec(
        tool_id="javascript",
        display_name="JavaScript Analyzer",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="web",
        version="1.0.0",
        language="python",
        description=(
            "In-process JavaScript intelligence: client-side attack-surface "
            "discovery via endpoints, routes, storage, auth, workers, wasm, "
            "security APIs, dynamic imports, third-party services and external "
            "domains, with strict-masked secret scanning and technology/"
            "dependency detection."
        ),
        capabilities=_CAPABILITIES,
        tags=("javascript", "in-process", "client-side", "attack-surface", "secrets"),
        accepts=("url", "host", "domain", "script"),
        required_inputs=("content", "url"),
        formats=("json",),
        arguments=(
            ToolArgument("content", "", "string", description="JavaScript source to analyse."),
            ToolArgument("url", "", "string", description="Absolute URL of the asset."),
            ToolArgument("asset_kind", "", "string", description="Asset kind (external/inline/bundle/...)."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Analyse supplied script content only; no acquisition.", safe=True),
            ToolExecutionMode("active", description="Analyse acquired script content with full detector set.", aggressive=False),
        ),
        limitations=(
            "Static analysis only; never executes the analysed script.",
            "Secret scanning emits masked indicators with confidence tiers, never raw values.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=(),
    ),
    JavaScriptToolSpec(
        tool_id="linkfinder",
        display_name="LinkFinder",
        vendor="Gerben",
        project_url="https://github.com/GerbenJavado/LinkFinder",
        license="GPL-3.0",
        subcategory="web",
        version="1.0.5",
        language="python",
        description="Extract endpoints from JavaScript files in a web application.",
        capabilities=("endpoint-extraction", "javascript-discovery"),
        tags=("javascript", "endpoint", "external"),
        accepts=("url",),
        required_inputs=("url",),
        formats=("text", "json"),
        arguments=(
            ToolArgument("script", "-i", "string", description="Local JS file to analyze."),
            ToolArgument("dump", "-d", "bool", description="Dump all matches."),
        ),
        modes=(ToolExecutionMode("active", description="Fetch a script and extract endpoints.", aggressive=False),),
        limitations=("Endpoint strings are candidates, not validated routes.",),
        installation_requirements=("git clone https://github.com/GerbenJavado/LinkFinder && pip install -r requirements.txt",),
        alternative_tools=("urlfinder", "xnlinkfinder"),
    ),
    JavaScriptToolSpec(
        tool_id="secretfinder",
        display_name="SecretFinder",
        vendor="m4ll0k",
        project_url="https://github.com/m4ll0k/SecretFinder",
        license="MIT",
        subcategory="web",
        version="1.0.0",
        language="python",
        description="Find sensitive data (API keys, tokens) inside JavaScript files.",
        capabilities=("secret-discovery", "token-discovery"),
        tags=("javascript", "secrets", "external"),
        accepts=("url",),
        required_inputs=("url",),
        formats=("json",),
        arguments=(ToolArgument("script", "-i", "string", description="Local JS file to analyze."),),
        modes=(ToolExecutionMode("active", description="Fetch a script and extract secret candidates.", aggressive=False),),
        limitations=("Detections are masked candidates requiring validation.",),
        installation_requirements=("git clone https://github.com/m4ll0k/SecretFinder && pip install -r requirements.txt",),
        alternative_tools=("gitleaks", "trufflehog"),
    ),
    JavaScriptToolSpec(
        tool_id="xnlinkfinder",
        display_name="xnLinkFinder",
        vendor="xnl-h4ck3r",
        project_url="https://github.com/xnl-h4ck3r/xnLinkFinder",
        license="MIT",
        subcategory="web",
        version="1.0.0",
        language="python",
        description="Extract endpoints from JavaScript files across multiple sources.",
        capabilities=("endpoint-extraction", "javascript-discovery"),
        tags=("javascript", "endpoint", "external"),
        accepts=("url",),
        required_inputs=("url",),
        formats=("text",),
        arguments=(
            ToolArgument("in_scope", "-sp", "bool", description="Only output in-scope endpoints."),
            ToolArgument("secrets", "-sf", "bool", description="Extract secret-like strings too."),
        ),
        modes=(ToolExecutionMode("active", description="Fetch a script and extract endpoints.", aggressive=False),),
        limitations=("Endpoint strings are candidates, not validated routes.",),
        installation_requirements=("git clone https://github.com/xnl-h4ck3r/xnLinkFinder && pip install -r requirements.txt",),
        alternative_tools=("urlfinder", "linkfinder"),
    ),
)


def register_javascript_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated JavaScript tool into ``tip`` (REGISTERED state)."""
    for spec in _JAVASCRIPT_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def javascript_tool_specs() -> tuple[JavaScriptToolSpec, ...]:
    """Return the JavaScript tool profiles registered by :func:`register_javascript_tools`."""
    return _JAVASCRIPT_TOOLS


def _metadata(spec: JavaScriptToolSpec) -> ToolMetadata:
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
        community_score=70.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: JavaScriptToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("asset_kind", "parent_url", "content_hash", "source"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="javascript-analyses",
            normalizer="javascript-normalizer",
            event_types=(
                "javascript.analysis.started",
                "javascript.asset.analysed",
                "javascript.secret.discovered",
                "javascript.analysis.completed",
            ),
            evidence_capture=("javascript", "evidence"),
        ),
        cli_binary="",
        cli_structure="library",
        arguments=spec.arguments,
        modes=spec.modes
        or (ToolExecutionMode("passive", description="Analyse supplied script content.", safe=True),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(
            ToolDependency(capability="python", description="JavaScript analysis runs in-process"),
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Analyse in-scope script assets only, through configured scope.",),
        common_mistakes=("Analysing out-of-scope scripts or executing untrusted content.",),
        examples=(f"{spec.tool_id} url=https://example.com/app.js",),
        references=tuple(url for url in (spec.project_url,) if url),
    )


def _compatibility(spec: JavaScriptToolSpec) -> ToolCompatibility:
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
