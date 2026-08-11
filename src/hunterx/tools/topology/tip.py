# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for the topology capability.

Registers the integrated network-mapping tool (traceroute) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can recommend
it by taxonomy capability (``route-mapping``, ``network-topology``). The
profile mirrors the Tool Integration SDK adapter descriptor so intelligence and
execution never disagree about a tool's contract.
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

#: Shared mission profiles that exercise the network-mapping capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the topology tool set.
_ASSESSMENTS = ("external", "attack-surface")


@dataclass(frozen=True, slots=True)
class TopologyToolSpec:
    """A single network-mapping tool profile for TIP registration."""

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
    accepts: tuple[str, ...] = ("ip",)
    required_inputs: tuple[str, ...] = ("ip",)
    formats: tuple[str, ...] = ("json", "text")
    cli_binary: str = ""
    cli_structure: str = "flags"
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_TOPOLOGY_TOOLS: tuple[TopologyToolSpec, ...] = (
    TopologyToolSpec(
        tool_id="traceroute",
        display_name="traceroute",
        vendor="The Linux Foundation",
        project_url="https://github.com/mpihlak/traceroute",
        license="GPL-2.0",
        subcategory="network",
        version="2.1.0",
        language="c",
        description="Map the network path (hop-by-hop route) to a target IP or host.",
        capabilities=("route-mapping", "network-topology"),
        tags=("routing", "topology", "hops"),
        accepts=("ip", "host", "domain"),
        required_inputs=("ip",),
        formats=("text", "json"),
        cli_binary="traceroute",
        arguments=(
            ToolArgument("numeric", "-n", "bool", description="Use numeric addresses only."),
            ToolArgument("max_hops", "-m", "int", description="Maximum hop count."),
            ToolArgument("first_ttl", "-f", "int", description="First TTL to start from."),
            ToolArgument("wait", "-w", "int", description="Seconds to wait per probe."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Single-path route discovery with numeric output.", safe=True),
        ),
        limitations=(
            "Route hops can be unreachable (asterisk) depending on network policy.",
            "ICMP/UDP probes may be filtered on some networks.",
        ),
        installation_requirements=("apt install traceroute", "choco install traceroute"),
        alternative_tools=("tracepath", "mtr"),
    ),
)


def register_topology_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated topology tool into ``tip`` (REGISTERED state)."""
    for spec in _TOPOLOGY_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def topology_tool_specs() -> tuple[TopologyToolSpec, ...]:
    """Return the topology tool profiles registered by :func:`register_topology_tools`."""
    return _TOPOLOGY_TOOLS


def _metadata(spec: TopologyToolSpec) -> ToolMetadata:
    return ToolMetadata(
        tool_id=spec.tool_id,
        display_name=spec.display_name,
        vendor=spec.vendor,
        project_url=spec.project_url,
        license=spec.license,
        category="topology",
        subcategory=spec.subcategory,
        version=spec.version,
        platforms=("linux", "darwin", "windows"),
        architectures=("amd64", "arm64"),
        language=spec.language,
        execution_type=ToolExecutionType.BINARY,
        package_manager="apt",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.MEDIUM,
        community_score=80.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: TopologyToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("max_hops", "first_ttl", "wait"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="topology-route-parser",
            normalizer="topology-route-normalizer",
            event_types=("output.collected", "topology.relationship.discovered"),
            evidence_capture=("routes",),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes
        or (ToolExecutionMode("passive", description="Route discovery.", safe=True),),
        safe_mode="passive",
        aggressive_mode="passive",
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Run against in-scope IP targets to enrich network topology.",),
        common_mistakes=("Tracing routes to out-of-scope addresses.",),
        examples=(f"{spec.tool_id} -n example.com",),
        references=(spec.project_url,),
    )


def _compatibility(spec: TopologyToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "darwin", "windows"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=True,
        cloud=True,
        air_gapped=False,
    )
