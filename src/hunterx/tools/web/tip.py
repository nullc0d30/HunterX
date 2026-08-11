# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Web Crawling.

Registers the web crawling tools (crawler, katana) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
them by taxonomy capability (``web-crawling``, ``web-discovery``). The profiles
mirror the tool descriptors used by the Tool Integration SDK adapters (same
version pins) so intelligence and execution never disagree about a tool's
contract.
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

#: Shared mission profiles that exercise the web crawling capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the web crawling tool set.
_ASSESSMENTS = ("external", "attack-surface")

#: Shared web crawling capability identifiers.
_CAPABILITIES = ("web-crawling", "web-discovery")


@dataclass(frozen=True, slots=True)
class WebToolSpec:
    """A single web crawling tool profile for TIP registration."""

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


_WEB_TOOLS: tuple[WebToolSpec, ...] = (
    WebToolSpec(
        tool_id="crawler",
        display_name="HunterX Crawler",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="web",
        version="1.0.0",
        language="python",
        description="In-process bounded web crawler producing canonical crawl observations.",
        capabilities=_CAPABILITIES,
        tags=("crawler", "in-process", "crawl", "web"),
        accepts=("url", "host", "domain"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="",
        cli_structure="library",
        arguments=(
            ToolArgument("depth", "", "int", description="Maximum crawl depth from a seed."),
            ToolArgument("max_pages", "", "int", description="Maximum number of pages to fetch."),
            ToolArgument("respect_robots", "", "bool", description="Honor robots.txt in the crawl."),
            ToolArgument("follow_subdomains", "", "bool", description="Crawl subdomains of roots."),
        ),
        modes=(
            ToolExecutionMode(
                "active",
                description="Bounded in-scope crawl fetching pages and following links.",
                aggressive=False,
            ),
            ToolExecutionMode("passive", description="Seed resolution and scope checks only.", safe=True),
        ),
        limitations=(
            "Does not execute JavaScript; client-rendered content requires a browser-assisted tool.",
            "Crawl is bounded by depth, page count and scope policy.",
        ),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=("katana",),
    ),
    WebToolSpec(
        tool_id="katana",
        display_name="Katana",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/katana",
        license="MIT",
        subcategory="web",
        version="1.1.2",
        language="go",
        description="Fast, headless-chrome-capable web crawler for large surface discovery.",
        capabilities=_CAPABILITIES + ("headless-browser",),
        tags=("katana", "crawler", "web", "projectdiscovery"),
        accepts=("url", "host", "domain"),
        required_inputs=("url",),
        formats=("json", "jsonl"),
        cli_binary="katana",
        arguments=(
            ToolArgument("depth", "-d", "int", description="Crawl depth passed to katana."),
            ToolArgument("scope", "-cs", "string", description="Scope value passed to katana."),
            ToolArgument(
                "excluded_extensions",
                "-ef",
                "string",
                description="Comma-separated file extensions excluded from the crawl.",
            ),
        ),
        modes=(
            ToolExecutionMode(
                "active",
                description="Crawl in-scope pages with JavaScript rendering enabled.",
                aggressive=False,
            ),
            ToolExecutionMode("passive", description="Crawl without JavaScript rendering.", safe=True),
        ),
        limitations=(
            "Headless-chrome mode requires a browser executable on the host.",
            "Crawl scope must be pinned with -cs to avoid scope drift.",
        ),
        installation_requirements=("go install -v github.com/projectdiscovery/katana/cmd/katana@latest",),
        alternative_tools=("crawler",),
    ),
    WebToolSpec(
        tool_id="gospider",
        display_name="Gospider",
        vendor="Jaeles",
        project_url="https://github.com/jaeles-project/gospider",
        license="MIT",
        subcategory="web",
        version="1.1.6",
        language="go",
        description="Fast web crawler that collects URLs, subdomains, endpoints and files.",
        capabilities=("web-crawling", "endpoint-discovery"),
        tags=("crawler", "web", "go"),
        accepts=("url", "host", "domain"),
        required_inputs=("url",),
        formats=("json", "jsonl"),
        cli_binary="gospider",
        arguments=(
            ToolArgument("depth", "-d", "int", description="Maximum crawl depth."),
            ToolArgument("threads", "-c", "int", description="Concurrent crawler threads."),
            ToolArgument("include_subdomains", "--include-subs", "bool", description="Crawl discovered subdomains."),
        ),
        modes=(ToolExecutionMode("active", description="Crawl in-scope pages and links.", aggressive=False),),
        limitations=("No JavaScript rendering; scope must be pinned.",),
        installation_requirements=("go install -v github.com/jaeles-project/gospider@latest",),
        alternative_tools=("katana", "hakrawler"),
    ),
    WebToolSpec(
        tool_id="hakrawler",
        display_name="Hakrawler",
        vendor="hakluke",
        project_url="https://github.com/hakluke/hakrawler",
        license="GPL-3.0",
        subcategory="web",
        version="2.1.0",
        language="go",
        description="Simple, fast web crawler designed for quick discovery of endpoints and assets.",
        capabilities=("web-crawling", "endpoint-discovery"),
        tags=("crawler", "web", "go"),
        accepts=("url", "host", "domain"),
        required_inputs=("url",),
        formats=("text", "json"),
        cli_binary="hakrawler",
        arguments=(
            ToolArgument("depth", "-depth", "int", description="Maximum crawl depth."),
            ToolArgument("plain", "-plain", "bool", description="Only output URLs."),
        ),
        modes=(ToolExecutionMode("active", description="Crawl in-scope pages.", aggressive=False),),
        limitations=("Simple crawler; no scope isolation beyond the seed.",),
        installation_requirements=("go install -v github.com/hakluke/hakrawler@latest",),
        alternative_tools=("katana", "gospider"),
    ),
    WebToolSpec(
        tool_id="gau",
        display_name="GAU",
        vendor="lc",
        project_url="https://github.com/lc/gau",
        license="MIT",
        subcategory="url",
        version="1.5.10",
        language="go",
        description="Fetch known URLs from historical passive sources (wayback, otx, commoncrawl).",
        capabilities=("historical-url-discovery", "endpoint-discovery"),
        tags=("url", "passive", "historical"),
        accepts=("domain",),
        required_inputs=("domain",),
        formats=("text", "json"),
        cli_binary="gau",
        arguments=(
            ToolArgument("threads", "--threads", "int", description="Concurrent worker threads."),
            ToolArgument("subdomains", "--subs", "bool", description="Include subdomains of the target."),
            ToolArgument("providers", "--providers", "list", description="Passive providers to query."),
        ),
        modes=(ToolExecutionMode("passive", description="Query historical sources only.", safe=True),),
        limitations=("Depends on third-party passive sources; not exhaustive.",),
        installation_requirements=("go install -v github.com/lc/gau/v2/cmd/gau@latest",),
        alternative_tools=("waybackurls", "urlfinder"),
    ),
    WebToolSpec(
        tool_id="waybackurls",
        display_name="Waybackurls",
        vendor="tomnomnom",
        project_url="https://github.com/tomnomnom/waybackurls",
        license="MIT",
        subcategory="url",
        version="0.1.0",
        language="go",
        description="Fetch all known URLs for a domain from the Wayback Machine CDX API.",
        capabilities=("historical-url-discovery", "endpoint-discovery"),
        tags=("url", "passive", "wayback"),
        accepts=("domain",),
        required_inputs=("domain",),
        formats=("text",),
        cli_binary="waybackurls",
        arguments=(
            ToolArgument("dates", "-dates", "bool", description="Include timestamped snapshots."),
            ToolArgument("subdomains", "-subs", "bool", description="Include subdomains."),
        ),
        modes=(ToolExecutionMode("passive", description="Query the Wayback CDX API.", safe=True),),
        limitations=("Only covers URLs archived by the Wayback Machine.",),
        installation_requirements=("go install -v github.com/tomnomnom/waybackurls@latest",),
        alternative_tools=("gau", "urlfinder"),
    ),
    WebToolSpec(
        tool_id="urlfinder",
        display_name="URLFinder",
        vendor="pingc0y",
        project_url="https://github.com/pingc0y/URLFinder",
        license="MIT",
        subcategory="url",
        version="1.0.0",
        language="go",
        description="Discover URLs, endpoints and API references from web content and JavaScript.",
        capabilities=("endpoint-discovery", "javascript-discovery"),
        tags=("url", "endpoint", "javascript"),
        accepts=("url", "host"),
        required_inputs=("url",),
        formats=("text", "json"),
        cli_binary="urlfinder",
        arguments=(
            ToolArgument("recursive", "-r", "bool", description="Recursively crawl discovered content."),
            ToolArgument("max_depth", "-d", "int", description="Maximum crawl depth."),
        ),
        modes=(ToolExecutionMode("active", description="Fetch pages and extract links/endpoints.", aggressive=False),),
        limitations=("Crawls the target only; discovered hosts stay data.",),
        installation_requirements=("go install -v github.com/pingc0y/URLFinder@latest",),
        alternative_tools=("gau", "waybackurls"),
    ),
)


def register_web_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated web crawling tool into ``tip`` (REGISTERED state)."""
    for spec in _WEB_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def web_tool_specs() -> tuple[WebToolSpec, ...]:
    """Return the web crawling tool profiles registered by :func:`register_web_tools`."""
    return _WEB_TOOLS


def _metadata(spec: WebToolSpec) -> ToolMetadata:
    in_process = spec.tool_id == "crawler"
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
        package_manager="pip" if in_process else "go",
        container_available=True,
        binary_available=not in_process,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH if not in_process else ProjectActivity.MEDIUM,
        community_score=88.0 if not in_process else 75.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: WebToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("depth", "max_pages", "seed_urls", "scope_roots", "respect_robots"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="web-observations",
            normalizer="web-normalizer",
            event_types=(
                "crawl.url-discovered",
                "crawl.endpoint-discovered",
                "crawl.websocket-discovered",
                "crawl.graphql-discovered",
            ),
            evidence_capture=("urls", "endpoints", "evidence"),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes or (ToolExecutionMode("active", description="Crawl the target.", aggressive=False),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(
            (ToolDependency(capability="python", description="In-process crawler runs without binaries"),)
            if spec.tool_id == "crawler"
            else ()
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Crawl in-scope web assets only, honoring robots.txt and rate limits.",),
        common_mistakes=("Crawling out-of-scope hosts or ignoring robots.txt directives.",),
        examples=(f"{spec.tool_id} {spec.accepts[0]}",),
        references=tuple(url for url in (spec.project_url,) if url),
    )


def _compatibility(spec: WebToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=spec.tool_id == "crawler",
        cloud=True,
        air_gapped=False,
    )
