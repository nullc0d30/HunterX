# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Live Host & Service Discovery.

Registers the live discovery tools (nmap, naabu, masscan, tcp-connect) into a
:class:`ToolIntelligenceAPI` so the Planner and selection engines can
recommend them by taxonomy capability (``host-discovery``, ``port-scanning``,
``service-fingerprint``). The profiles mirror the tool descriptors used by the
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

#: Shared mission profiles that exercise the live discovery capability.
_MISSIONS = ("external-pentest", "internal-pentest", "bug-bounty", "continuous")

#: Input/output contract labels for the live discovery tool set.
_ASSESSMENTS = ("external", "internal", "attack-surface")


@dataclass(frozen=True, slots=True)
class LiveToolSpec:
    """A single live discovery tool profile for TIP registration."""

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
    formats: tuple[str, ...] = ("json", "xml", "text")
    cli_binary: str = ""
    cli_structure: str = "flags"
    arguments: tuple[ToolArgument, ...] = ()
    modes: tuple[ToolExecutionMode, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_LIVE_TOOLS: tuple[LiveToolSpec, ...] = (
    LiveToolSpec(
        tool_id="nmap",
        display_name="Nmap",
        vendor="Nmap Project",
        project_url="https://nmap.org",
        license="Nmap Public Source License",
        subcategory="network",
        version="7.95",
        language="c",
        description="Flexible network discovery, port scanning and service/version detection.",
        capabilities=("host-discovery", "port-scanning", "service-fingerprint"),
        tags=("nmap", "scanning", "fingerprinting", "tls"),
        accepts=("ip", "cidr", "host", "domain"),
        required_inputs=("ip",),
        formats=("xml", "text"),
        cli_binary="nmap",
        arguments=(
            ToolArgument("ports", "-p", "list", description="Ports to probe."),
            ToolArgument("protocol", "-sT/-sU", "string", description="Transport protocol(s) to scan."),
            ToolArgument("service_detection", "-sV", "bool", description="Enable service/version detection."),
            ToolArgument("with_tls", "--script ssl-cert", "bool", description="Collect TLS certificate metadata."),
            ToolArgument("host_discovery_only", "-sn", "bool", description="Run host discovery only."),
            ToolArgument("rate_limit", "--max-rate", "int", description="Maximum packets per second."),
            ToolArgument("min_hostgroup", "--min-hostgroup", "int", description="Minimum parallel host group size."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Host discovery via responses to configured probes.", safe=True),
            ToolExecutionMode("active", description="Port and service scanning of in-scope targets.", aggressive=True),
        ),
        limitations=(
            "UDP scanning is slow; service fingerprinting sends probe traffic.",
            "Syn scans require raw-socket privileges on some platforms.",
        ),
        installation_requirements=("apt install nmap", "choco install nmap"),
        alternative_tools=("naabu", "masscan", "tcp-connect"),
    ),
    LiveToolSpec(
        tool_id="naabu",
        display_name="Naabu",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/naabu",
        license="MIT",
        subcategory="network",
        version="2.3.4",
        language="go",
        description="Fast port scanner by ProjectDiscovery with configurable rate control.",
        capabilities=("host-discovery", "port-scanning"),
        tags=("naabu", "scanning", "ports"),
        accepts=("ip", "cidr", "host", "domain"),
        required_inputs=("ip",),
        formats=("json", "text"),
        cli_binary="naabu",
        arguments=(
            ToolArgument("ports", "-p", "list", description="Ports to probe."),
            ToolArgument("protocol", "-sU", "string", description="Enable UDP scanning."),
            ToolArgument("rate_limit", "-rate", "int", description="Maximum packets per second."),
            ToolArgument("threads", "-c", "int", description="Concurrent scan threads."),
            ToolArgument("timeout", "-timeout", "int", description="Per-host timeout in milliseconds."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Connect-based probing of configured ports.", safe=True),
            ToolExecutionMode("active", description="SYN-scan with raw sockets.", aggressive=True),
        ),
        limitations=("Reports only open ports; no service fingerprinting.",),
        installation_requirements=("go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",),
        alternative_tools=("nmap", "tcp-connect"),
    ),
    LiveToolSpec(
        tool_id="masscan",
        display_name="Masscan",
        vendor="Robert Graham",
        project_url="https://github.com/robertdavidgraham/masscan",
        license="AGPL-3.0",
        subcategory="network",
        version="1.3.2",
        language="c",
        description="High-throughput TCP port scanner for large address ranges.",
        capabilities=("host-discovery", "port-scanning"),
        tags=("masscan", "scanning", "high-throughput"),
        accepts=("ip", "cidr"),
        required_inputs=("ip",),
        formats=("json", "text"),
        cli_binary="masscan",
        arguments=(
            ToolArgument("ports", "-p", "list", description="Ports to probe."),
            ToolArgument("protocol", "-sU", "string", description="Enable UDP scanning."),
            ToolArgument("rate_limit", "--rate", "int", description="Maximum packets per second."),
            ToolArgument("adapter", "--adapter", "string", description="Source adapter used for the scan."),
            ToolArgument("source_port", "--source-port", "int", description="Source port to use."),
        ),
        modes=(ToolExecutionMode("active", description="High-throughput SYN/UDP scanning.", aggressive=True),),
        limitations=(
            "SYN scanning requires raw sockets/root; can saturate networks if misconfigured.",
            "No service fingerprinting.",
        ),
        installation_requirements=("apt install masscan", "choco install masscan"),
        alternative_tools=("nmap", "naabu"),
    ),
    LiveToolSpec(
        tool_id="tcp-connect",
        display_name="TCP Connect Probe",
        vendor="HunterX",
        project_url="",
        license="Apache-2.0",
        subcategory="network",
        version="1.0.0",
        language="python",
        description="In-process TCP-connect host reachability and port discovery.",
        capabilities=("host-discovery", "port-scanning"),
        tags=("tcp-connect", "in-process", "fallback"),
        accepts=("ip", "host"),
        required_inputs=("ip",),
        formats=("json",),
        cli_binary="",
        cli_structure="library",
        arguments=(
            ToolArgument("ports", "", "list", description="Ports to probe."),
            ToolArgument("timeout", "", "number", description="Per-connect timeout in seconds."),
        ),
        modes=(
            ToolExecutionMode("passive", description="Plain TCP connect probes with per-port timeouts.", safe=True),
        ),
        limitations=("TCP only; no service fingerprinting; timeouts are inconclusive for reachability.",),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        alternative_tools=("nmap", "naabu"),
    ),
    LiveToolSpec(
        tool_id="rustscan",
        display_name="RustScan",
        vendor="RustScan Project",
        project_url="https://github.com/RustScan/RustScan",
        license="GPL-3.0",
        subcategory="network",
        version="2.2.1",
        language="rust",
        description="Ultra-fast port scanner with batching and JSON output.",
        capabilities=("host-discovery", "port-scanning"),
        tags=("port-scan", "rust", "fast"),
        accepts=("ip", "host", "domain", "cidr"),
        required_inputs=("ip",),
        formats=("json", "text"),
        cli_binary="rustscan",
        arguments=(
            ToolArgument("ports", "-p", "string", description="Port range(s) to scan."),
            ToolArgument("threads", "-t", "int", description="Number of threads per batch."),
            ToolArgument("batches", "-b", "int", description="Number of target batches."),
            ToolArgument("timeout", "--timeout", "int", description="Connection timeout in milliseconds."),
        ),
        modes=(ToolExecutionMode("active", description="Fast SYN/connect scanning in batches.", aggressive=True),),
        limitations=("Port discovery only; hand off to nmap for service fingerprinting.",),
        installation_requirements=("cargo install rustscan", "apt install rustscan"),
        alternative_tools=("nmap", "naabu"),
    ),
)


def register_live_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated live discovery tool into ``tip`` (REGISTERED state)."""
    for spec in _LIVE_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def live_tool_specs() -> tuple[LiveToolSpec, ...]:
    """Return the live discovery tool profiles registered by :func:`register_live_tools`."""
    return _LIVE_TOOLS


def _metadata(spec: LiveToolSpec) -> ToolMetadata:
    in_process = spec.tool_id == "tcp-connect"
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
        community_score=85.0 if not in_process else 70.0,
        description=spec.description,
        tags=spec.tags,
    )


def _package_manager(tool_id: str) -> str:
    if tool_id in ("naabu",):
        return "go"
    if tool_id == "rustscan":
        return "cargo"
    return "apt"


def _knowledge(spec: LiveToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("ports", "protocol", "rate_limit", "timeout"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="live-observations",
            normalizer="live-normalizer",
            event_types=("host.discovery.completed",),
            evidence_capture=("observations",),
        ),
        cli_binary=spec.cli_binary or spec.tool_id,
        cli_structure=spec.cli_structure,
        arguments=spec.arguments,
        modes=spec.modes or (ToolExecutionMode("active", description="Active scanning.", aggressive=True),),
        safe_mode="passive",
        aggressive_mode="active",
        authentication_requirements="none",
        privileges_required="user" if spec.tool_id in ("nmap", "naabu") else "root",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        dependencies=(
            (ToolDependency(capability="python", description="TCP connect is performed in-process"),)
            if spec.tool_id == "tcp-connect"
            else ()
        ),
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Scan in-scope addresses only, through configured port/rate policies.",),
        common_mistakes=("Scanning out-of-scope networks or exceeding authorized rates.",),
        examples=(f"{spec.tool_id} {spec.accepts[0]}",),
        references=tuple(url for url in (spec.project_url,) if url),
    )


def _compatibility(spec: LiveToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=spec.tool_id == "tcp-connect",
        cloud=True,
        air_gapped=False,
    )
