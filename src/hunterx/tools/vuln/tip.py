# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool Intelligence Platform registration for Vulnerability Knowledge.

Registers the vulnerability knowledge provider adapters (NVD, CISA KEV, EPSS,
MITRE CWE, vendor advisory, OSV/GHSA) into a :class:`ToolIntelligenceAPI` so
the Planner and selection engines can recommend them by taxonomy capability
(``vulnerability-knowledge``, ``cve-intelligence``, ``epss-intelligence``,
``kev-intelligence``). The profiles mirror the tool descriptors used by the
Tool Integration SDK adapters so intelligence and execution never disagree
about a provider's contract.
"""

from __future__ import annotations

from dataclasses import dataclass

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
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolScopeProfile,
)
from hunterx.tools.intelligence.api import ToolIntelligenceAPI

#: Mission profiles that exercise the vulnerability knowledge capability.
_MISSIONS = ("external-pentest", "bug-bounty", "continuous", "audit")

#: Capability identifiers advertised by the provider set.
_CAPABILITIES = ("vulnerability-knowledge", "cve-intelligence")

#: Output contract labels for the provider set.
_EVENT_TYPES = ("vulnerability.knowledge.source.updated", "vulnerability.cve.discovered")


@dataclass(frozen=True, slots=True)
class VulnerabilityProviderSpec:
    """A single knowledge provider profile for TIP registration."""

    provider_id: str
    display_name: str
    vendor: str
    version: str
    description: str
    capabilities: tuple[str, ...]
    tags: tuple[str, ...]


_VULNERABILITY_PROVIDERS: tuple[VulnerabilityProviderSpec, ...] = (
    VulnerabilityProviderSpec(
        provider_id="nvd-cve",
        display_name="NVD CVE",
        vendor="NIST",
        version="1.0.0",
        description="Normalizes NVD CVE feed/API payloads into canonical vulnerability records.",
        capabilities=_CAPABILITIES + ("nvd",),
        tags=("nvd", "cve", "knowledge", "normalizer"),
    ),
    VulnerabilityProviderSpec(
        provider_id="cisa-kev",
        display_name="CISA KEV",
        vendor="CISA",
        version="1.0.0",
        description="Normalizes CISA Known Exploited Vulnerabilities catalog entries.",
        capabilities=_CAPABILITIES + ("kev-intelligence", "cisa-kev"),
        tags=("cisa", "kev", "knowledge", "normalizer"),
    ),
    VulnerabilityProviderSpec(
        provider_id="epss",
        display_name="EPSS",
        vendor="FIRST.org",
        version="1.0.0",
        description="Normalizes EPSS score rows (CSV or JSON) into canonical EPSS records.",
        capabilities=_CAPABILITIES + ("epss-intelligence", "epss"),
        tags=("first", "epss", "knowledge", "normalizer"),
    ),
    VulnerabilityProviderSpec(
        provider_id="mitre-cwe",
        display_name="MITRE CWE",
        vendor="MITRE",
        version="1.0.0",
        description="Normalizes MITRE CWE weakness records into the canonical CWE model.",
        capabilities=_CAPABILITIES + ("cwe-intelligence", "mitre-cwe"),
        tags=("mitre", "cwe", "knowledge", "normalizer"),
    ),
    VulnerabilityProviderSpec(
        provider_id="vendor-advisory",
        display_name="Vendor Advisory",
        vendor="Vendors",
        version="1.0.0",
        description="Normalizes vendor security advisories into the canonical advisory model.",
        capabilities=_CAPABILITIES + ("advisory-intelligence", "vendor-advisory"),
        tags=("advisory", "vendor", "knowledge", "normalizer"),
    ),
    VulnerabilityProviderSpec(
        provider_id="osv",
        display_name="OSV/GHSA",
        vendor="OSV",
        version="1.0.0",
        description="Normalizes OSV/GHSA advisory records into canonical vulnerabilities.",
        capabilities=_CAPABILITIES + ("osv-intelligence", "ghsa", "osv"),
        tags=("osv", "ghsa", "knowledge", "normalizer"),
    ),
)


def register_vulnerability_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated knowledge provider into ``tip`` (REGISTERED state)."""
    for spec in _VULNERABILITY_PROVIDERS:
        tip.register_tool(
            _metadata(spec),
            knowledge=_knowledge(spec),
            compatibility=_compatibility(spec),
        )


def vulnerability_provider_specs() -> tuple[VulnerabilityProviderSpec, ...]:
    """Return the provider profiles registered by :func:`register_vulnerability_tools`."""
    return _VULNERABILITY_PROVIDERS


def _metadata(spec: VulnerabilityProviderSpec) -> ToolMetadata:
    return ToolMetadata(
        tool_id=spec.provider_id,
        display_name=spec.display_name,
        vendor=spec.vendor,
        project_url="",
        license="Apache-2.0",
        category="knowledge",
        subcategory="vulnerability",
        version=spec.version,
        platforms=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        language="python",
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


def _knowledge(spec: VulnerabilityProviderSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.provider_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=("external", "attack-surface"),
        supported_mission_profiles=_MISSIONS,
        inputs=ToolInputContract(
            accepts=("knowledge",),
            required=("raw",),
            optional=("source",),
        ),
        outputs=ToolOutputContract(
            formats=("json",),
            parser="vulnerability-knowledge",
            normalizer="vulnerability-normalizer",
            event_types=_EVENT_TYPES,
            evidence_capture=("vulnerabilities", "knowledge"),
        ),
        cli_binary="",
        cli_structure="library",
        arguments=(),
        modes=(
            ToolExecutionMode(
                "normalize",
                description="Normalize provider payload into canonical vulnerability knowledge.",
                safe=True,
            ),
        ),
        safe_mode="normalize",
        aggressive_mode="normalize",
        authentication_requirements="none",
        privileges_required="user",
        limitations=(
            "In-process normalization only; provider data must be supplied as static payloads.",
            "Never performs vulnerability validation or exploitation.",
        ),
        known_issues=(),
        installation_requirements=("Bundled with HunterX; no external tool required.",),
        dependencies=(),
        alternative_tools=tuple(
            other.provider_id
            for other in _VULNERABILITY_PROVIDERS
            if other.provider_id != spec.provider_id
        ),
        recommended_usage=("Refresh canonical vulnerability knowledge through configured sources only.",),
        common_mistakes=("Treating normalized knowledge as validated findings.",),
        examples=(f"{spec.provider_id} knowledge",),
        references=(),
    )


def _compatibility(spec: VulnerabilityProviderSpec) -> ToolCompatibility:
    return ToolCompatibility(
        tool_id=spec.provider_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=True,
        containerized=False,
        native=True,
        cloud=True,
        air_gapped=False,
    )


@dataclass(frozen=True, slots=True)
class VulnerabilityScannerSpec:
    """A single vulnerability scanner profile for TIP registration."""

    tool_id: str
    display_name: str
    vendor: str
    project_url: str
    license: str
    version: str
    language: str
    description: str
    capabilities: tuple[str, ...]
    tags: tuple[str, ...]


#: Mission profiles that exercise active vulnerability scanning.
_SCANNER_MISSIONS = ("external-pentest", "bug-bounty", "continuous", "audit")

#: Capability identifiers advertised by the scanner set.
_SCANNER_CAPABILITIES = ("vulnerability-scan", "template-scan")

_VULNERABILITY_SCANNERS: tuple[VulnerabilityScannerSpec, ...] = (
    VulnerabilityScannerSpec(
        tool_id="nuclei",
        display_name="nuclei",
        vendor="ProjectDiscovery",
        project_url="https://github.com/projectdiscovery/nuclei",
        license="MIT",
        version="3.2.0",
        language="go",
        description="Template-based vulnerability scanner for web, DNS, network and infrastructure.",
        capabilities=_SCANNER_CAPABILITIES,
        tags=("nuclei", "scanner", "templates", "vulnerability"),
    ),
)


def register_vulnerability_scanner_tools(tip: ToolIntelligenceAPI) -> None:
    """Register every integrated vulnerability scanner into ``tip``."""
    for spec in _VULNERABILITY_SCANNERS:
        tip.register_tool(
            _scanner_metadata(spec),
            knowledge=_scanner_knowledge(spec),
            compatibility=_scanner_compatibility(spec),
        )


def vulnerability_scanner_specs() -> tuple[VulnerabilityScannerSpec, ...]:
    """Return the scanner profiles registered by :func:`register_vulnerability_scanner_tools`."""
    return _VULNERABILITY_SCANNERS


def _scanner_metadata(spec: VulnerabilityScannerSpec) -> ToolMetadata:
    return ToolMetadata(
        tool_id=spec.tool_id,
        display_name=spec.display_name,
        vendor=spec.vendor,
        project_url=spec.project_url,
        license=spec.license,
        category="assessment",
        subcategory="vulnerability",
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
        community_score=90.0,
        description=spec.description,
        tags=spec.tags,
    )


def _scanner_knowledge(spec: VulnerabilityScannerSpec) -> ToolKnowledge:
    return ToolKnowledge(
        tool_id=spec.tool_id,
        canonical_name=spec.tool_id,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=("external", "attack-surface"),
        supported_mission_profiles=_SCANNER_MISSIONS,
        inputs=ToolInputContract(
            accepts=("url", "host", "domain", "ip"),
            required=("url",),
            optional=(
                "templates",
                "severity",
                "tags",
                "exclude_tags",
                "rate_limit",
                "concurrency",
                "timeout",
                "follow_redirects",
                "silent",
                "no_interactsh",
                "output",
            ),
            transforms=(),
            max_targets_per_invocation=1,
        ),
        outputs=ToolOutputContract(
            formats=("jsonl",),
            parser="nuclei-jsonl",
            normalizer="vulnerability-candidate-normalizer",
            event_types=("arsenal.vulnerability.candidate",),
            evidence_capture=("candidates",),
            dedup_key_spec=("template_id", "target", "matched_at"),
        ),
        cli_binary="nuclei",
        cli_structure="flags",
        arguments=(
            ToolArgument("url", "-u", "string", required=True, description="Target to scan."),
            ToolArgument("templates", "-t", "string", description="Templates to run."),
            ToolArgument("severity", "-severity", "string", description="Severity filter."),
            ToolArgument("tags", "-tags", "string", description="Include tags."),
            ToolArgument("exclude_tags", "-etags", "string", description="Exclude tags."),
            ToolArgument("rate_limit", "-rl", "int", description="Requests per second."),
            ToolArgument("concurrency", "-c", "int", description="Parallel templates."),
            ToolArgument("timeout", "-timeout", "int", description="Request timeout seconds."),
            ToolArgument("follow_redirects", "-fr", "bool", description="Follow redirects."),
            ToolArgument("silent", "-silent", "bool", description="Suppress verbose logging."),
            ToolArgument("no_interactsh", "-no-interactsh", "bool", description="Disable OAST callbacks."),
            ToolArgument("output", "-o", "path", description="JSONL report artifact."),
        ),
        modes=(
            ToolExecutionMode(
                "scan",
                description="Run template-based scan against the target (active detection).",
                safe=False,
            ),
        ),
        safe_mode="scan",
        aggressive_mode="scan",
        authentication_requirements="none",
        privileges_required="user",
        limitations=(
            "Nuclei output is a candidate observation; every match requires validation before it becomes a finding.",
            "OAST/interactsh callbacks are disabled by default for scoped safety.",
        ),
        known_issues=(),
        installation_requirements=("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",),
        dependencies=(),
        alternative_tools=("nikto", "trivy"),
        recommended_usage=("Run only against in-scope targets; validate every candidate before reporting.",),
        common_mistakes=("Promoting raw template matches to findings without validation.",),
        examples=("nuclei -u https://example.com -jsonl -silent -no-interactsh",),
        references=(spec.project_url,),
        supported_targets=("url", "host", "domain", "ip"),
        supported_protocols=("http", "https", "dns", "tcp"),
        supported_vulnerabilities=(),
        supported_evidence_types=("http-response", "matcher", "extracted-result"),
        supported_proof_strategies=(),
        input_schema=ToolInputSchema(
            fields=(
                ToolInputField("url", "string", required=True, scope_linked=True, description="Target to scan."),
                ToolInputField("templates", "string", description="Templates to run."),
                ToolInputField("severity", "string", description="Severity filter."),
                ToolInputField("tags", "string", description="Include tags."),
                ToolInputField("exclude_tags", "string", description="Exclude tags."),
                ToolInputField("rate_limit", "int", description="Requests per second."),
                ToolInputField("concurrency", "int", description="Parallel templates."),
                ToolInputField("timeout", "int", description="Request timeout seconds."),
                ToolInputField("follow_redirects", "bool", description="Follow redirects."),
                ToolInputField("silent", "bool", description="Suppress verbose logging."),
                ToolInputField("no_interactsh", "bool", description="Disable OAST callbacks."),
                ToolInputField("output", "path", description="JSONL report artifact."),
            ),
            required=("url",),
            optional=(
                "templates",
                "severity",
                "tags",
                "exclude_tags",
                "rate_limit",
                "concurrency",
                "timeout",
                "follow_redirects",
                "silent",
                "no_interactsh",
                "output",
            ),
            target_type="url",
            scope="inherit",
            rate_limits=(),
            timeout=120.0,
            output_format="jsonl",
            execution_mode="scan",
        ),
        output_schema=ToolOutputSchema(
            fields=(
                ToolOutputField("template_id", "string", "Template identifier.", required=True),
                ToolOutputField("template_name", "string", "Template display name."),
                ToolOutputField("severity", "string", "Reported severity.", required=True),
                ToolOutputField("matched_at", "string", "Matched URL/endpoint."),
                ToolOutputField("matcher", "string", "Matcher that fired."),
                ToolOutputField("extracted_results", "array", "Extracted result strings."),
                ToolOutputField("metadata", "object", "Template metadata subset."),
                ToolOutputField("cve_ids", "array", "Associated CVE identifiers."),
                ToolOutputField("timestamp", "string", "Match timestamp."),
                ToolOutputField("target", "string", "Scanned target.", required=True),
                ToolOutputField("template_type", "string", "Template type (http/dns/...)."),
                ToolOutputField("confidence", "float", "Candidate confidence."),
                ToolOutputField("requires_validation", "boolean", "Always true for candidates.", required=True),
            ),
            required_fields=("template_id", "severity", "target", "requires_validation"),
            formats=("jsonl",),
        ),
        invocation_contract=ToolInvocationContract(
            command="nuclei",
            arguments=(
                ToolInputField("url", "string", required=True, scope_linked=True),
                ToolInputField("templates", "string"),
                ToolInputField("severity", "string"),
                ToolInputField("tags", "string"),
                ToolInputField("exclude_tags", "string"),
                ToolInputField("rate_limit", "int"),
                ToolInputField("concurrency", "int"),
                ToolInputField("timeout", "int"),
                ToolInputField("follow_redirects", "bool"),
                ToolInputField("silent", "bool"),
                ToolInputField("no_interactsh", "bool"),
                ToolInputField("output", "path"),
            ),
            stdin=False,
            timeout=120.0,
            network_policy="scoped",
            filesystem_policy="read-only",
            scope_policy="inherit",
            safety_policy="low-impact-active",
            expected_exit_codes=(0,),
            expected_output_formats=("jsonl",),
        ),
        configuration_contract="matches are candidates and require validation before promotion",
        resource_requirements=ToolResourceRequirements(
            cpu_estimate=60.0,
            memory_estimate_mb=512.0,
            network_estimate="scoped",
            disk_estimate_mb=128.0,
            timeout=120.0,
            concurrency_class="medium",
            rate_limit=None,
        ),
        safety_profile=ToolSafetyProfile(
            safety_class=ToolSafetyClass.LOW_IMPACT_ACTIVE,
            destructive=False,
            requires_authorization=False,
            allowed_for=_SCANNER_MISSIONS,
        ),
        scope_profile=ToolScopeProfile(
            follows_redirects=False,
            redirect_scope="inherit",
            expands_scope=False,
            network_boundary="target",
        ),
        parser_id="nuclei-jsonl",
        normalizer_id="vulnerability-candidate-normalizer",
        adapter_id="hunterx.tools.vuln.nuclei:NucleiAdapter",
        version_constraints=(">=3.0.0",),
        known_false_positives=("Template matches require manual validation; not all are exploitable.",),
        known_false_negatives=("Templates outside the active set; OAST detection disabled by default.",),
        provenance={"source": "sprint-024", "category": "vulnerability", "license": "MIT"},
        knowledge_version="1.0.0",
    )


def _scanner_compatibility(spec: VulnerabilityScannerSpec) -> ToolCompatibility:
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


#: Confidence ceiling: nuclei template matches are candidates awaiting validation.
NUCLEI_CONFIDENCE_CEILING = ToolConfidenceCeiling(
    tool_id="nuclei",
    detection_ceiling=0.8,
    behavioral_ceiling=0.6,
    proof_ceiling=0.3,
)
