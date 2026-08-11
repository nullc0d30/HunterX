# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Technology Fingerprinting.

Registers the fingerprinting tools (httpx, whatweb, signature) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
them by taxonomy capability (``technology-fingerprinting``,
``http-metadata``). The profiles mirror the tool descriptors used by the Tool
Integration SDK adapters (same version pins) so intelligence and execution
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

#: Shared mission profiles that exercise the fingerprinting capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the fingerprinting tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared fingerprinting capability identifiers.
_CAPABILITIES = ("technology-fingerprinting",)


@dataclass(frozen=True, slots=True)
class TechToolSpec:
    """A single fingerprinting tool profile for TIP registration."""

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
    accepts: tuple[str, ...] = ("url", "host")
    required_inputs: tuple[str, ...] = ("url",)
    formats: tuple[str, ...] = ("json",)
    cli_binary: str = ""
    cli_structure: str = "flags"
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_TECH_TOOLS: tuple[TechToolSpec, ...] = (
    TechToolSpec(
        tool_id="httpx",
        display_name="httpx",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/httpx",
        license="MIT",
        subcategory="web",
        version="1.3.9",
        language="go",
        description="Fast multi-purpose HTTP(S) toolkit with technology detection.",
        capabilities=_CAPABILITIES + ("http-metadata",),
        tags=("httpx", "fingerprinting", "http", "cdn"),
        accepts=("url", "host", "domain", "ip"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="httpx",
        arguments=(
            ToolArgument("cdn", "-cdn", "bool", description="Detect CDN providers."),
            ToolArgument("tls_grab", "-tls-grab", "bool", description="Collect TLS certificate metadata."),
            ToolArgument("threads", "-threads", "int", description="Concurrent scan threads."),
            ToolArgument("rate_limit", "-rate-limit", "int", description="Maximum HTTP requests per second."),
            ToolArgument("timeout", "-timeout", "int", description="Per-request timeout in seconds."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Probe in-scope HTTP(S) endpoints for metadata.", safe=True),
            ToolExecutionMode("active", description="Technology detection against in-scope endpoints.", aggressive=False),
        ),
        limitations=(
            "Technology detection depends on fingerprintable response markers.",
            "CDN detection is heuristic and may be reported as unknown.",
        ),
        installation_requirements=("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",),
        alternative_tools=("whatweb", "signature"),
    ),
    TechToolSpec(
        tool_id="whatweb",
        display_name="WhatWeb",
        vendor="WhatWeb",
        project_url="https://github.com/urbanadventurer/WhatWeb",
        license="GPL-2.0",
        subcategory="web",
        version="0.5.5",
        language="ruby",
        description="Deep web technology fingerprinting scanner with a large plugin database.",
        capabilities=_CAPABILITIES,
        tags=("whatweb", "fingerprinting", "web", "cms"),
        accepts=("url", "host", "domain"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="whatweb",
        arguments=(
            ToolArgument("aggression", "--aggression", "int", description="Aggression level (1-4)."),
            ToolArgument("follow_redirects", "--follow-redirect", "bool", description="Follow HTTP redirects."),
            ToolArgument("user_agent", "--user-agent", "string", description="Custom user agent string."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Banner and metadata fingerprinting only.", safe=True),
            ToolExecutionMode("active", description="Aggressive fingerprinting with probing.", aggressive=True),
        ),
        limitations=(
            "Aggressive levels send additional probes; keep aggression at 1 for passive postures.",
            "Requires a Ruby runtime and the WhatWeb gem.",
        ),
        installation_requirements=("gem install whatweb", "apt install whatweb"),
        alternative_tools=("httpx", "signature"),
    ),
    TechToolSpec(
        tool_id="signature",
        display_name="Signature Detector",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="web",
        version="1.0.0",
        language="python",
        description="In-process signature-based technology detection over HTTP evidence.",
        capabilities=_CAPABILITIES,
        tags=("signature", "in-process", "fallback", "fingerprinting"),
        accepts=("url", "host", "domain", "ip"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="",
        cli_structure="library",
        arguments=(
            ToolArgument("scheme", "", "string", description="Preferred scheme (https or http)."),
            ToolArgument("fallback", "", "bool", description="Fall back to the alternate scheme."),
            ToolArgument("timeout", "", "number", description="Per-fetch timeout in seconds."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Read-only HTTP fetches with signature matching.", safe=True),
        ),
        limitations=(
            "Curated signature database only; covers common web technologies.",
            "Detection is heuristic and confidence is evidence-based.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=("httpx", "whatweb"),
    ),
)


def register_tech_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated fingerprinting tool into ``tip`` (REGISTERED state)."""
    for spec in _TECH_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def tech_tool_specs() -> tuple[TechToolSpec, ...]:
    """Return the fingerprinting tool profiles registered by :func:`register_tech_tools`."""
    return _TECH_TOOLS


def _metadata(spec: TechToolSpec) -> ToolMetadata:
    in_process = spec.tool_id == "signature"
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
        execution_type=ToolExecutionType.PIP if in_process else ToolExecutionType.BINARY,
        package_manager="pip" if in_process else _package_manager(spec.tool_id),
        container_available=True,
        binary_available=not in_process,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=90.0 if spec.tool_id == "httpx" else (80.0 if not in_process else 70.0),
        description=spec.description,
        tags=spec.tags,
    )


def _package_manager(tool_id: str) -> str:
    return "go" if tool_id == "httpx" else "gem"


def _knowledge(spec: TechToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("scheme", "fallback", "timeout", "cdn", "tls_grab"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="technology-observations",
            normalizer="technology-normalizer",
            event_types=("technology.detected",),
            evidence_capture=("technologies", "evidence"),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes or (ToolExecutionMode("active", description="Technology detection.", aggressive=False),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(
            (ToolDependency(capability="python", description="Signature detection runs in-process"),)
            if spec.tool_id == "signature"
            else ()
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Fingerprint in-scope HTTP(S) endpoints only, through configured scope.",),
        common_mistakes=("Fingerprinting out-of-scope endpoints or exceeding configured rates.",),
        examples=(f"{spec.tool_id} {spec.accepts[0]}",),
        references=tuple(url for url in (spec.project_url,) if url),
    )


def _compatibility(spec: TechToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=spec.tool_id == "signature",
        cloud=True,
        air_gapped=False,
    )
