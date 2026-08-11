# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for the recon capability.

Registers the six integrated recon tools (Subfinder, Amass, Assetfinder,
Findomain, BBOT, theHarvester) into a :class:`ToolIntelligenceAPI` so the
Planner and selection engines can recommend them by taxonomy capability
(``subdomain-discovery``, ``host-discovery``, ``dns-records``,
``certificate-lookup``, ``whois-lookup``). The profiles mirror the tool
descriptors used by the Tool Integration SDK adapters (same version pins) so
intelligence and execution never disagree about a tool's contract.
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolExecutionMode,
    ToolExecutionType,
    ToolInputContract,
    ToolKnowledge,
    ToolMetadata,
    ToolOutputContract,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Shared mission profiles that exercise the recon capability.
_MISSIONS = ("external-pentest", "bug-bounty", "web-security")

#: Input/output contract labels for the recon tool set.
_ASSESSMENTS = ("external", "attack-surface")


@dataclass(frozen=True, slots=True)
class ReconToolSpec:
    """A single recon tool profile for TIP registration."""

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
    accepts: tuple[str, ...] = ("domain",)
    required_inputs: tuple[str, ...] = ("domain",)
    formats: tuple[str, ...] = ("json", "text")
    cli_binary: str = ""
    cli_structure: str = "flags"
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_RECON_TOOLS: tuple[ReconToolSpec, ...] = (
    ReconToolSpec(
        tool_id="subfinder",
        display_name="Subfinder",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/subfinder",
        license="MIT",
        subcategory="dns",
        version="2.14.0",
        language="go",
        description="Fast passive subdomain enumeration from curated online sources.",
        capabilities=("subdomain-discovery", "host-discovery", "dns-records"),
        tags=("osint", "passive", "subdomain"),
        arguments=(
            ToolArgument("sources", "-s", "list", description="Passive sources to query."),
            ToolArgument("rate_limit", "-rl", "int", description="Maximum HTTP requests per second."),
            ToolArgument("threads", "-t", "int", description="Concurrent goroutines for active resolution."),
            ToolArgument("resolvers", "-r", "list", description="Comma-separated custom resolvers."),
            ToolArgument("max_time", "-max-time", "int", description="Maximum minutes to wait for enumeration."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Passive sources only.", safe=True),
            ToolExecutionMode("active", description="Actively resolve discovered subdomains.", aggressive=True),
        ),
        limitations=("Passive sources can lag behind live infrastructure.",),
        installation_requirements=("go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",),
        alternative_tools=("amass", "bbot", "findomain"),
    ),
    ReconToolSpec(
        tool_id="amass",
        display_name="Amass",
        vendor="OWASP",
        project_url="https://github.com/owasp-amass/amass",
        license="Apache-2.0",
        subcategory="dns",
        version="4.2.0",
        language="go",
        description="In-depth attack surface mapping and external asset discovery.",
        capabilities=("subdomain-discovery", "host-discovery", "dns-records"),
        tags=("attack-surface", "enumeration", "asn"),
        arguments=(
            ToolArgument("mode", "", "choice", choices=("passive", "active"), description="Enumeration posture."),
            ToolArgument("timeout", "-timeout", "int", description="Minutes before stopping the enumeration."),
            ToolArgument("wordlist", "-w", "string", description="Wordlist for brute forcing."),
            ToolArgument("json", "-json", "string", description="Write output to a JSON file."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Passive sources only.", safe=True),
            ToolExecutionMode("active", description="Active enumeration with resolution.", aggressive=True),
        ),
        limitations=("Active enumeration can be slow and network intensive.",),
        installation_requirements=("go install -v github.com/owasp-amass/amass/v4/...@master",),
        alternative_tools=("subfinder", "bbot", "assetfinder"),
    ),
    ReconToolSpec(
        tool_id="assetfinder",
        display_name="Assetfinder",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/assetfinder",
        license="MIT",
        subcategory="dns",
        version="0.4.0",
        language="go",
        description="Lightweight tool for finding domains and subdomains potentially related to a target.",
        capabilities=("subdomain-discovery",),
        tags=("osint", "subdomain"),
        formats=("text",),
        arguments=(
            ToolArgument("subs_only", "--subs-only", "bool", description="Only include subdomains."),
        ),
        modes=(ToolExecutionMode("passive", description="Index scraping only.", safe=True),),
        limitations=("No active resolution; results may contain stale entries.",),
        installation_requirements=("go install -v github.com/projectdiscovery/assetfinder/cmd/assetfinder@latest",),
        alternative_tools=("subfinder", "findomain", "bbot"),
    ),
    ReconToolSpec(
        tool_id="findomain",
        display_name="Findomain",
        vendor="Findomain",
        project_url="https://github.com/Findomain/Findomain",
        license="GPL-3.0",
        subcategory="dns",
        version="9.0.1",
        language="rust",
        description="Subdomain enumeration with certificate transparency, PTR and zone walking.",
        capabilities=("subdomain-discovery", "certificate-lookup", "dns-records"),
        tags=("osint", "subdomain", "certificate"),
        arguments=(
            ToolArgument("quiet", "-q", "bool", description="Only print discovered subdomains."),
            ToolArgument("ip", "-i", "bool", description="Resolve subdomains and print their IP addresses."),
            ToolArgument("resolvers", "-r", "bool", description="Enumerate resolvers."),
            ToolArgument("wordlist", "-w", "string", description="Wordlist for brute forcing."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Passive sources only.", safe=True),
            ToolExecutionMode("active", description="Resolve and verify discovered subdomains.", aggressive=True),
        ),
        limitations=("Active modes require working resolvers.",),
        installation_requirements=("cargo install findomain",),
        alternative_tools=("subfinder", "amass", "theharvester"),
    ),
    ReconToolSpec(
        tool_id="bbot",
        display_name="BBOT",
        vendor="Black Lantern Security",
        project_url="https://github.com/blacklanternsecurity/bbot",
        license="GPL-3.0",
        subcategory="attack-surface",
        version="2.3.0",
        language="python",
        description="Modular, recursive attack surface discovery with passive and active modules.",
        capabilities=("subdomain-discovery", "host-discovery"),
        tags=("attack-surface", "osint", "modular"),
        cli_structure="subcommand",
        arguments=(
            ToolArgument("target", "-t", "string", required=True, description="Root domain to enumerate."),
            ToolArgument("flags", "-f", "list", description="Module flags/presets (e.g. subdomain-enum)."),
            ToolArgument("recursive", "-rf", "choice", choices=("passive", "active"), description="Recursion level."),
            ToolArgument("json", "--json", "bool", description="Emit NDJSON events."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Passive modules only.", safe=True),
            ToolExecutionMode("active", description="Active modules with verification.", aggressive=True),
        ),
        limitations=("Heavier than single-purpose tools; requires Python environment.",),
        installation_requirements=("pipx install bbot",),
        alternative_tools=("amass", "subfinder"),
    ),
    ReconToolSpec(
        tool_id="theharvester",
        display_name="theHarvester",
        vendor="Sekaia",
        project_url="https://github.com/laramies/theHarvester",
        license="GPL-2.0",
        subcategory="dns",
        version="4.3.0",
        language="python",
        description="E-mail, subdomain and hostname recon from public sources.",
        capabilities=("subdomain-discovery", "host-discovery", "dns-records", "certificate-lookup", "whois-lookup"),
        tags=("osint", "email", "subdomain"),
        arguments=(
            ToolArgument("domain", "-d", "string", required=True, description="Root domain to enumerate."),
            ToolArgument("sources", "-b", "list", description="Data sources to query."),
            ToolArgument("limit", "-l", "int", description="Limit of results per source."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Passive source collection.", safe=True),
            ToolExecutionMode("active", description="Aggressive source collection.", aggressive=True),
        ),
        limitations=("Source rate limits can throttle large runs.",),
        installation_requirements=("git clone https://github.com/laramies/theHarvester && pip install -r requirements.txt",),
        alternative_tools=("subfinder", "findomain", "bbot"),
    ),
)


def register_recon_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated recon tool into ``tip`` (REGISTERED state)."""
    for spec in _RECON_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def recon_tool_specs() -> tuple[ReconToolSpec, ...]:
    """Return the recon tool profiles registered by :func:`register_recon_tools`."""
    return _RECON_TOOLS


def _metadata(spec: ReconToolSpec) -> ToolMetadata:
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
        execution_type=ToolExecutionType.BINARY,
        package_manager="go",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=spec.tool_id == "subfinder" and 95.0 or 80.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: ReconToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("timeout", "threads"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="recon-json",
            normalizer="recon-normalizer",
            event_types=("output.collected",),
            evidence_capture=("discoveries",),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes or (
            ToolExecutionMode("passive", description="Passive source collection.", safe=True),
            ToolExecutionMode("active", description="Active collection and resolution.", aggressive=True),
        ),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Run passive mode against in-scope domains before active scanning.",),
        common_mistakes=("Enumerating out-of-scope domains.",),
        examples=(f"{spec.tool_id} -d example.com",),
        references=(spec.project_url,),
    )


def _compatibility(spec: ReconToolSpec) -> ToolCompatibility:
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
