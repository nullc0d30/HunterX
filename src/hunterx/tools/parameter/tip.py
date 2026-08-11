# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for parameter discovery.

Registers the parameter discovery tools (arjun, paramspider, kiterunner) into
a :class:`ToolIntelligenceAPI` so the Planner and selection engines can
recommend them by taxonomy capability (``parameter-discovery``,
``get-parameter-discovery``, ``post-parameter-discovery``,
``historical-parameter-discovery``).
"""

from __future__ import annotations

from dataclasses import dataclass

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolExecutionType,
    ToolInputContract,
    ToolKnowledge,
    ToolMetadata,
    ToolOutputContract,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

_MISSIONS = ("external-pentest", "bug-bounty", "web-security")
_ASSESSMENTS = ("external", "attack-surface")


@dataclass(frozen=True, slots=True)
class ParameterToolSpec:
    """A single parameter discovery tool profile for TIP registration."""

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
    accepts: tuple[str, ...] = ("url",)
    required_inputs: tuple[str, ...] = ("url",)
    formats: tuple[str, ...] = ("json", "text")
    cli_binary: str = ""
    arguments: tuple[ToolArgument, ...] = ()
    limitations: tuple[str, ...] = ()
    installation_requirements: tuple[str, ...] = ()
    alternative_tools: tuple[str, ...] = ()


_PARAMETER_TOOLS: tuple[ParameterToolSpec, ...] = (
    ParameterToolSpec(
        tool_id="arjun",
        display_name="Arjun",
        vendor="s0md3v",
        project_url="https://github.com/s0md3v/Arjun",
        license="AGPL-3.0",
        subcategory="parameter",
        version="2.2.6",
        language="python",
        description="HTTP parameter discovery for GET and POST requests.",
        capabilities=("parameter-discovery", "get-parameter-discovery", "post-parameter-discovery"),
        tags=("parameter", "fuzzing", "python"),
        accepts=("url", "host"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="arjun",
        arguments=(
            ToolArgument("method", "-m", "string", description="HTTP method to probe (GET/POST)."),
            ToolArgument("wordlist", "-w", "path", description="Path to the parameter wordlist."),
            ToolArgument("threads", "-t", "int", description="Concurrent workers."),
        ),
        limitations=("Active probing; may be noisy against production endpoints.",),
        installation_requirements=("pip install arjun",),
        alternative_tools=("paramspider", "ffuf"),
    ),
    ParameterToolSpec(
        tool_id="paramspider",
        display_name="ParamSpider",
        vendor="devploit",
        project_url="https://github.com/devploit/ParamSpider",
        license="MIT",
        subcategory="parameter",
        version="1.0.0",
        language="python",
        description="Passive parameter discovery from archived URLs.",
        capabilities=("parameter-discovery", "historical-parameter-discovery"),
        tags=("parameter", "passive", "wayback"),
        accepts=("domain",),
        required_inputs=("domain",),
        formats=("text",),
        cli_binary="paramspider",
        arguments=(
            ToolArgument("level", "--level", "string", description="Crawl depth for archived URLs."),
            ToolArgument("exclude", "-e", "list", description="Extensions to exclude."),
        ),
        limitations=("Passive only; relies on archived URL availability.",),
        installation_requirements=("git clone https://github.com/devploit/ParamSpider && pip install -r requirements.txt",),
        alternative_tools=("arjun", "gau"),
    ),
    ParameterToolSpec(
        tool_id="kiterunner",
        display_name="Kiterunner",
        vendor="assetnote",
        project_url="https://github.com/assetnote/kiterunner",
        license="GPL-3.0",
        subcategory="parameter",
        version="1.0.0",
        language="go",
        description="Route and endpoint discovery using wordlists of common API paths.",
        capabilities=("endpoint-discovery", "api-discovery"),
        tags=("endpoint", "api", "route"),
        accepts=("url", "host"),
        required_inputs=("url",),
        formats=("json",),
        cli_binary="kr",
        arguments=(
            ToolArgument("wordlist", "-w", "path", description="Path to the route wordlist.", required=True),
            ToolArgument("threads", "-t", "int", description="Concurrent workers."),
        ),
        limitations=("Requires the kiterunner wordlist (kr-wordlist).",),
        installation_requirements=("go install -v github.com/assetnote/kiterunner@latest",),
        alternative_tools=("ffuf", "gobuster"),
    ),
)


def register_parameter_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated parameter discovery tool into ``tip``."""
    for spec in _PARAMETER_TOOLS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def parameter_tool_specs() -> tuple[ParameterToolSpec, ...]:
    """Return the parameter tool profiles registered."""
    return _PARAMETER_TOOLS


def _metadata(spec: ParameterToolSpec) -> ToolMetadata:
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
        package_manager="pip" if spec.tool_id in {"arjun", "paramspider"} else "go",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=80.0,
        description=spec.description,
        tags=spec.tags,
    )


def _knowledge(spec: ParameterToolSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=_ASSESSMENTS,
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=spec.accepts,
            required=spec.required_inputs,
            optional=("method", "wordlist", "threads", "level", "exclude"),
        ),
        outputs=ToolOutputContract(
            formats=spec.formats,
            parser="parameter-json",
            normalizer="parameter-normalizer",
            event_types=("parameter.discovered",),
            evidence_capture=("parameters",),
        ),
        cli_binary=spec.cli_binary,
        cli_structure="flags",
        arguments=spec.arguments,
        authentication_requirements="none",
        privileges_required="user",
        limitations=spec.limitations,
        known_issues=(),
        installation_requirements=spec.installation_requirements,
        alternative_tools=spec.alternative_tools,
        recommended_usage=("Discover in-scope parameters only; never fuzz production beyond scope.",),
        common_mistakes=("Treating discovered parameters as validated inputs.",),
        references=(spec.project_url,),
    )


def _compatibility(spec: ParameterToolSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        native=True,
        cloud=True,
        air_gapped=False,
    )
