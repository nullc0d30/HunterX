# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Content Discovery.

Registers the content discovery tools (ffuf) into a
:class:`ToolIntelligenceAPI` with the full Sprint 023 contracts: typed input
schema, output schema, invocation contract, safety profile, scope profile and
resource requirements. The wordlist field is marked ``scope_linked``/data-only
and the safety class is bounded to ``ACTIVE`` for parameter fuzzing.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolArgument,
    ToolCompatibility,
    ToolConfidenceCeiling,
    ToolExecutionMode,
    ToolExecutionType,
    ToolInputContract,
    ToolInputField,
    ToolInputSchema,
    ToolInvocationContract,
    ToolKnowledge,
    ToolMetadata,
    ToolOutputContract,
    ToolOutputField,
    ToolOutputSchema,
    ToolRateLimitProfile,
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolScopeProfile,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Mission profiles that exercise content discovery.
_MISSIONS = ("web-security", "bug-bounty", "external-pentest")

#: Canonical capability identifiers advertised by the content tool set.
_CAPABILITIES = ("directory-discovery", "web-fuzzing", "parameter-discovery")

_CONTENT_TOOLS: tuple[ToolMetadata, ...] = (
    ToolMetadata(
        tool_id="ffuf",
        display_name="ffuf",
        vendor="Ffuf",
        project_url="https://github.com/ffuf/ffuf",
        license="MIT",
        category="assessment",
        subcategory="web",
        version="2.1.0",
        platforms=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        language="go",
        execution_type=ToolExecutionType.BINARY,
        package_manager="go",
        container_available=True,
        binary_available=True,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=92.0,
        description="Fast web fuzzer for content, directory and parameter discovery.",
        tags=("fuzzing", "content-discovery", "directory", "parameter"),
    ),
)


def register_content_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every content discovery tool into ``tip``."""
    for metadata in _CONTENT_TOOLS:
        tip.register_tool(
            metadata,
            knowledge=_knowledge(metadata),
            compatibility=_compatibility(metadata),
        )


def content_tool_ids() -> tuple[str, ...]:
    """Return the content tool ids registered by :func:`register_content_tools`."""
    return tuple(metadata.tool_id for metadata in _CONTENT_TOOLS)


def _knowledge(metadata: ToolMetadata) -> ToolKnowledge:
    tool_id = metadata.tool_id
    return ToolKnowledge(
        tool_id=tool_id,
        canonical_name=tool_id,
        purpose=metadata.description,
        capabilities=_CAPABILITIES,
        supported_assessments=("external", "attack-surface", "web"),
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=("url",),
            required=("url", "wordlist"),
            optional=("matcher", "filter_size", "threads", "rate_limit", "delay", "method"),
            transforms=("url-template",),
            max_targets_per_invocation=1,
        ),
        outputs=ToolOutputContract(
            formats=("json",),
            parser="ffuf-json",
            normalizer="content-normalizer",
            event_types=("arsenal.content.discovered",),
            evidence_capture=("requests",),
            dedup_key_spec=("url", "status", "size"),
        ),
        cli_binary="ffuf",
        cli_structure="flags",
        arguments=(
            ToolArgument("url", "-u", "url", required=True, description="Target URL template (FUZZ keyword)."),
            ToolArgument("wordlist", "-w", "path", required=True, description="Wordlist data file path."),
            ToolArgument("matcher", "-mc", "string", description="HTTP status matcher."),
            ToolArgument("filter_size", "-fs", "string", description="Response size filters (false-positive control)."),
            ToolArgument("threads", "-t", "int", description="Concurrent fuzzing threads."),
            ToolArgument("rate_limit", "-rate", "int", description="Maximum requests per second."),
            ToolArgument("delay", "-p", "float", description="Delay between requests in seconds."),
            ToolArgument("method", "-X", "string", choices=("GET", "POST", "PUT", "HEAD", "OPTIONS"), description="HTTP method."),
        ),
        modes=(
            ToolExecutionMode("directory", description="Directory and path discovery.", safe=True),
            ToolExecutionMode("parameter", description="Parameter/value fuzzing.", aggressive=True),
            ToolExecutionMode("combined", description="Directory and parameter fuzzing.", aggressive=True),
        ),
        safe_mode="directory",
        aggressive_mode="parameter",
        authentication_requirements="none",
        privileges_required="user",
        limitations=(
            "Heuristic results require validation; matching responses are candidates, not findings.",
            "Response-size filtering reduces but cannot eliminate false positives.",
        ),
        known_issues=(),
        performance_notes="Rate limits and thread caps are mandatory for governed execution.",
        installation_requirements=("go install github.com/ffuf/ffuf/v2@latest",),
        dependencies=(),
        alternative_tools=("katana",),
        recommended_usage=(
            "Always provide a validated wordlist data file and explicit matcher/filter bounds.",
            "Run directory mode before parameter mode and keep rate limits within scope policy.",
        ),
        common_mistakes=("Fuzzing out-of-scope hosts or passing wordlists from untrusted sources.",),
        examples=("ffuf -u https://example.com/FUZZ -w words.txt -mc 200,301,403",),
        references=(metadata.project_url,),
        supported_targets=("url",),
        supported_protocols=("http", "https"),
        supported_vulnerabilities=(),
        supported_evidence_types=("http-status", "response-size", "content-type"),
        supported_proof_strategies=(),
        input_schema=ToolInputSchema(
            fields=(
                ToolInputField("url", "url", required=True, scope_linked=True, description="Target URL template."),
                ToolInputField("wordlist", "path", required=True, scope_linked=True, description="Wordlist data file path."),
                ToolInputField("matcher", "string", description="HTTP status matcher."),
                ToolInputField("filter_size", "string", description="Response size filters."),
                ToolInputField("threads", "int", description="Concurrent threads."),
                ToolInputField("rate_limit", "int", description="Requests per second."),
                ToolInputField("delay", "float", description="Delay between requests."),
                ToolInputField("method", "choice", choices=("GET", "POST", "PUT", "HEAD", "OPTIONS"), description="HTTP method."),
            ),
            required=("url", "wordlist"),
            optional=("matcher", "filter_size", "threads", "rate_limit", "delay", "method"),
            target_type="url",
            scope="inherit",
            rate_limits=("target", "scope"),
            timeout=60.0,
            output_format="json",
            execution_mode="directory",
        ),
        output_schema=ToolOutputSchema(
            fields=(
                ToolOutputField("url", "url", "Discovered URL.", required=True),
                ToolOutputField("method", "string", "HTTP method used."),
                ToolOutputField("status", "int", "HTTP status code."),
                ToolOutputField("size", "int", "Response body size in bytes."),
                ToolOutputField("words", "int", "Response word count."),
                ToolOutputField("lines", "int", "Response line count."),
                ToolOutputField("content_type", "string", "Response content type."),
                ToolOutputField("redirect", "string", "Redirect location."),
            ),
            required_fields=("url",),
            formats=("json",),
        ),
        invocation_contract=ToolInvocationContract(
            command="ffuf",
            arguments=(
                ToolInputField("url", "url", required=True, scope_linked=True),
                ToolInputField("wordlist", "path", required=True, scope_linked=True),
                ToolInputField("matcher", "string"),
                ToolInputField("filter_size", "string"),
                ToolInputField("threads", "int"),
                ToolInputField("rate_limit", "int"),
                ToolInputField("delay", "float"),
                ToolInputField("method", "choice", choices=("GET", "POST", "PUT", "HEAD", "OPTIONS")),
            ),
            stdin=False,
            timeout=60.0,
            network_policy="scoped",
            filesystem_policy="read-only",
            scope_policy="inherit",
            safety_policy="active",
            expected_exit_codes=(0, 1),
            expected_output_formats=("json",),
        ),
        configuration_contract="wordlist is data, never executable content",
        resource_requirements=ToolResourceRequirements(
            cpu_estimate=30.0,
            memory_estimate_mb=128.0,
            network_estimate="medium",
            disk_estimate_mb=32.0,
            timeout=60.0,
            concurrency_class="medium",
            rate_limit=ToolRateLimitProfile(
                requests_per_second=10.0,
                concurrency=20,
                burst=50,
                cooldown_seconds=5.0,
                target_limits={},
            ),
        ),
        safety_profile=ToolSafetyProfile(
            safety_class=ToolSafetyClass.ACTIVE,
            destructive=False,
            requires_authorization=False,
            allowed_for=("web-security", "bug-bounty", "external-pentest"),
        ),
        scope_profile=ToolScopeProfile(
            follows_redirects=True,
            redirect_scope="inherit",
            expands_scope=False,
            network_boundary="inherit",
        ),
        parser_id="ffuf-json",
        normalizer_id="content-normalizer",
        adapter_id="hunterx.tools.content.ffuf:FfufAdapter",
        version_constraints=(">=2.0.0",),
        known_false_positives=("Default-error-page responses matching the matcher.",),
        known_false_negatives=("Filtered responses that are actually reachable.",),
        provenance={"source": "sprint-024", "category": "content", "license": "MIT"},
        knowledge_version="1.0.0",
    )


def _compatibility(metadata: ToolMetadata) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=metadata.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=True,
        cloud=True,
        air_gapped=False,
    )


#: Confidence ceiling: ffuf results are heuristics, never proof.
FFUF_CONFIDENCE_CEILING = ToolConfidenceCeiling(
    tool_id="ffuf",
    detection_ceiling=0.55,
    behavioral_ceiling=0.8,
    proof_ceiling=0.85,
)
