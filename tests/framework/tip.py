# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Shared TIP test fixtures: tool metadata/knowledge builders and a standard tool set.

The standard set models real-world tools without integrating them: a crawler
(katana-like), a port scanner (nmap-like), an HTTP prober (httpx-like) and a
fuzzer (ffuf-like). Tools reference each other through capability dependencies
so dependency, recommendation and validation tests share one registry.
"""

from __future__ import annotations

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


def make_metadata(
    tool_id: str,
    *,
    display_name: str = "",
    category: str = "analysis",
    subcategory: str = "code",
    version: str = "1.0.0",
    platforms: tuple[str, ...] = ("linux", "windows"),
    architectures: tuple[str, ...] = ("amd64",),
    execution_type: ToolExecutionType = ToolExecutionType.BINARY,
    community_score: float = 50.0,
    description: str = "",
    tags: tuple[str, ...] = (),
) -> ToolMetadata:
    """Build a :class:`ToolMetadata` with sane defaults."""
    return ToolMetadata(
        tool_id=tool_id,
        display_name=display_name or tool_id.title(),
        vendor="tip-fixture",
        project_url=f"https://example.invalid/{tool_id}",
        license="Apache-2.0",
        category=category,
        subcategory=subcategory,
        version=version,
        platforms=platforms,
        architectures=architectures,
        language="go",
        execution_type=execution_type,
        package_manager="apt",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=community_score,
        description=description or f"Fixture tool {tool_id}.",
        tags=tags,
    )


def make_knowledge(
    tool_id: str,
    *,
    capabilities: tuple[str, ...] = (),
    accepts: tuple[str, ...] = (),
    required_inputs: tuple[str, ...] = (),
    formats: tuple[str, ...] = ("json", "text"),
    missions: tuple[str, ...] = (),
    dependencies: tuple[ToolDependency, ...] = (),
    cli_binary: str = "",
    arguments: tuple[ToolArgument, ...] = (),
    modes: tuple[ToolExecutionMode, ...] = (),
) -> ToolKnowledge:
    """Build a :class:`ToolKnowledge` profile with sane defaults."""
    return ToolKnowledge(
        tool_id=tool_id,
        purpose=f"Fixture knowledge for {tool_id}.",
        capabilities=capabilities,
        supported_assessments=("web",),
        supported_mission_profiles=missions or ("web-security",),
        inputs=ToolInputContract(
            accepts=accepts,
            required=required_inputs,
            optional=("timeout",),
        ),
        outputs=ToolOutputContract(
            formats=formats,
            parser="json",
            normalizer="json-normalizer",
            event_types=("finding",),
        ),
        cli_binary=cli_binary or tool_id,
        cli_structure="subcommand",
        arguments=arguments,
        modes=modes or (ToolExecutionMode(id="safe", safe=True), ToolExecutionMode(id="thorough", aggressive=True)),
        safe_mode="safe",
        aggressive_mode="thorough",
        authentication_requirements="none",
        privileges_required="user",
        limitations=("fixture",),
        known_issues=(),
        installation_requirements=("install fixture",),
        dependencies=dependencies,
        alternative_tools=(),
        recommended_usage=("use in CI",),
        common_mistakes=(),
        examples=("fixture --example",),
        references=(),
    )


def make_compatibility(
    tool_id: str,
    *,
    os: tuple[str, ...] = ("linux", "windows"),
    architectures: tuple[str, ...] = ("amd64", "arm64"),
    python_versions: tuple[str, ...] = (),
    docker: bool = True,
    containerized: bool = False,
    native: bool = True,
    cloud: bool = True,
    air_gapped: bool = True,
) -> ToolCompatibility:
    """Build a :class:`ToolCompatibility` profile with sane defaults."""
    return ToolCompatibility(
        tool_id=tool_id,
        os=os,
        architectures=architectures,
        python_versions=python_versions,
        docker=docker,
        containerized=containerized,
        native=native,
        cloud=cloud,
        air_gapped=air_gapped,
    )


def register_standard_tools(tip: ToolIntelligenceAPI) -> None:
    """Register the standard tool set into ``tip`` (all in REGISTERED state)."""
    tip.register_tool(
        make_metadata(
            "katana",
            category="recon",
            subcategory="http",
            description="Crawl web applications to discover endpoints.",
            tags=("crawler", "recon"),
        ),
        knowledge=make_knowledge(
            "katana",
            capabilities=("web-crawling", "http-enumeration"),
            accepts=("url", "domain"),
            required_inputs=("url",),
            formats=("json", "text"),
            missions=("web-security", "bug-bounty"),
        ),
        compatibility=make_compatibility("katana"),
    )
    tip.register_tool(
        make_metadata(
            "nmap",
            category="recon",
            subcategory="network",
            description="Scan hosts for open ports and services.",
            tags=("scanner", "network"),
        ),
        knowledge=make_knowledge(
            "nmap",
            capabilities=("port-scanning", "service-fingerprint"),
            accepts=("host", "ip"),
            required_inputs=("host",),
            missions=("external-pentest", "internal-pentest"),
        ),
        compatibility=make_compatibility("nmap"),
    )
    tip.register_tool(
        make_metadata(
            "httpx",
            category="recon",
            subcategory="http",
            description="Probe live hosts and extract HTTP metadata.",
            tags=("prober", "http"),
        ),
        knowledge=make_knowledge(
            "httpx",
            capabilities=("host-discovery", "http-enumeration"),
            accepts=("host", "ip"),
            required_inputs=("host",),
            missions=("web-security", "external-pentest"),
        ),
        compatibility=make_compatibility("httpx"),
    )
    tip.register_tool(
        make_metadata(
            "ffuf",
            category="assessment",
            subcategory="web",
            description="Fuzz web endpoints for hidden behaviors.",
            tags=("fuzzer", "web"),
        ),
        knowledge=make_knowledge(
            "ffuf",
            capabilities=("web-fuzzing", "directory-discovery"),
            accepts=("url",),
            required_inputs=("url",),
            missions=("web-security", "bug-bounty"),
        ),
        compatibility=make_compatibility("ffuf"),
    )
