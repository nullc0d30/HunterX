# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for the DNS capability.

Registers the DNS tools (DNSx, dnspython) into a :class:`ToolIntelligenceAPI`
so the Planner and selection engines can recommend them by taxonomy capability
(``dns-records``, ``dns-resolution``, ``dnssec``, ``mail-infrastructure``,
``wildcard-detection``). The profiles mirror the tool descriptors used by the
Tool Integration SDK adapters (same version pins) so intelligence and
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

#: Shared mission profiles that exercise the DNS capability.
_MISSIONS = ("external-pentest", "bug-bounty", "web-security")

#: Input/output contract labels for the DNS tool set.
_ASSESSMENTS = ("external", "attack-surface")


@dataclass(frozen=True, slots=True)
class DnsToolSpec:
    """A single DNS tool profile for TIP registration."""

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


_DNS_TOOLS: tuple[DnsToolSpec, ...] = (
    DnsToolSpec(
        tool_id="dnsx",
        display_name="DNSx",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/dnsx",
        license="MIT",
        subcategory="dns",
        version="1.1.9",
        language="go",
        description="Fast and versatile DNS toolkit supporting multiple record types and resolvers.",
        capabilities=("dns-records", "dns-resolution", "dnssec"),
        tags=("dns", "resolution", "dnssec"),
        arguments=(
            ToolArgument("record_types", "", "list", description="Record types to query (a, aaaa, cname, mx, ns, txt, soa, ptr, srv, caa, ds, dnskey, any)."),
            ToolArgument("resolvers", "-r", "list", description="Comma-separated custom resolvers."),
            ToolArgument("rate_limit", "-rl", "int", description="Maximum queries per second."),
            ToolArgument("threads", "-t", "int", description="Concurrent queries."),
            ToolArgument("timeout", "-timeout", "int", description="Per-query timeout in seconds."),
            ToolArgument("retries", "-retry", "int", description="Retries for failed queries."),
            ToolArgument("wildcard", "-wd", "bool", description="Filter wildcard responses."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Query only authoritative/public resolvers.", safe=True),
            ToolExecutionMode("active", description="Aggressive multi-resolver resolution.", aggressive=True),
        ),
        limitations=("JSON output requires -j; wildcard filtering is heuristic.",),
        installation_requirements=("go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",),
        alternative_tools=("dnspython",),
    ),
    DnsToolSpec(
        tool_id="dnspython",
        display_name="dnspython",
        vendor="dnspython project",
        project_url="https://github.com/rthalley/dnspython",
        license="ISC",
        subcategory="dns",
        version="2.8.0",
        language="python",
        description="High-level DNS toolkit performing direct resolution with configurable resolvers.",
        capabilities=("dns-records", "dns-resolution", "dnssec"),
        tags=("dns", "resolution", "library"),
        cli_binary="",
        cli_structure="library",
        arguments=(
            ToolArgument("record_types", "", "list", description="Record types to resolve."),
            ToolArgument("resolvers", "", "list", description="Resolver addresses to query through."),
            ToolArgument("timeout", "", "int", description="Per-query timeout in seconds."),
            ToolArgument("lifetime", "", "int", description="Total lifetime for one query in seconds."),
        ),
        modes=(ToolExecutionMode("active", description="Direct resolution through configured resolvers.", aggressive=True),),
        limitations=("Active only; requires network egress to resolvers.",),
        installation_requirements=("pip install dnspython",),
        alternative_tools=("dnsx",),
    ),
    DnsToolSpec(
        tool_id="massdns",
        display_name="MassDNS",
        vendor="blechschmidt",
        project_url="https://github.com/blechschmidt/massdns",
        license="MIT",
        subcategory="dns",
        version="1.4.0",
        language="c",
        description="High-performance DNS stub resolver for bulk subdomain resolution.",
        capabilities=("brute-force-dns", "dns-records", "dns-resolution"),
        tags=("dns", "brute-force", "bulk"),
        arguments=(
            ToolArgument("domains", "", "list", description="Domain list to resolve."),
            ToolArgument("resolvers", "-r", "list", description="Comma-separated resolver IPs."),
            ToolArgument("record_type", "-t", "string", description="Record type to query (default A)."),
            ToolArgument("queries_per_second", "-s", "int", description="Maximum queries per second."),
            ToolArgument("threads", "-n", "int", description="Number of resolver threads."),
        ),
        modes=(ToolExecutionMode("active", description="Bulk resolution across many resolvers.", aggressive=True),),
        limitations=("Requires root/raw sockets for very high throughput.",),
        installation_requirements=("git clone https://github.com/blechschmidt/massdns && make",),
        alternative_tools=("shuffledns", "dnsx"),
    ),
    DnsToolSpec(
        tool_id="shuffledns",
        display_name="Shuffledns",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/shuffledns",
        license="MIT",
        subcategory="dns",
        version="1.0.9",
        language="go",
        description="Fast subdomain brute-forcing wrapper around massdns.",
        capabilities=("brute-force-dns", "subdomain-discovery", "dns-resolution"),
        tags=("dns", "brute-force", "subdomain"),
        arguments=(
            ToolArgument("wordlist", "-w", "path", description="Path to the subdomain wordlist.", required=True),
            ToolArgument("resolvers", "-r", "path", description="Path to the resolver list."),
            ToolArgument("threads", "-t", "int", description="Concurrent resolution threads."),
            ToolArgument("wildcard", "-wildcard", "bool", description="Perform wildcard filtering."),
        ),
        modes=(ToolExecutionMode("active", description="Brute-force subdomain resolution.", aggressive=True),),
        limitations=("Wordlist-driven; requires a resolvers file.",),
        installation_requirements=("go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",),
        alternative_tools=("massdns",),
    ),
)


def register_dns_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated DNS tool into ``tip`` (REGISTERED state)."""
    for spec in _DNS_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def dns_tool_specs() -> tuple[DnsToolSpec, ...]:
    """Return the DNS tool profiles registered by :func:`register_dns_tools`."""
    return _DNS_TOOLS


def _metadata(spec: DnsToolSpec) -> ToolMetadata:
    binary = spec.tool_id in {"dnsx", "massdns", "shuffledns"}
    pip = spec.tool_id == "dnspython"
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
        execution_type=ToolExecutionType.BINARY if binary else ToolExecutionType.PIP,
        package_manager="pip" if pip else ("go" if spec.tool_id in {"dnsx", "shuffledns"} else "git"),
        container_available=True,
        binary_available=binary,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=90.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: DnsToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("resolvers", "timeout"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="dns-json",
            normalizer="dns-normalizer",
            event_types=("dns.resolution.completed",),
            evidence_capture=("dns_records",),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes or (ToolExecutionMode("active", description="Active resolution.", aggressive=True),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(ToolDependency(capability="python", description="dnspython is imported in-process"),) if spec.tool_id == "dnspython" else (),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Resolve in-scope domains through configured resolvers only.",),
        common_mistakes=("Querying out-of-scope names or internal infrastructure.",),
        examples=(f"{spec.tool_id} -d example.com",),
        references=(spec.project_url,),
    )


def _compatibility(spec: DnsToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=spec.tool_id == "dnspython",
        cloud=True,
        air_gapped=False,
    )
