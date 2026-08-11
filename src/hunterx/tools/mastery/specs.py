# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Arsenal tool specs — compact declarative profiles for the full arsenal.

Each :class:`ToolSpec` expands into a complete :class:`ToolMasterProfile`
(identity + knowledge + support classification + evidence/proof semantics +
chaining + safety). This is the authoritative data source for the
``capabilities/universal-security-arsenal.json`` manifest.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from hunterx.domain.tool_intelligence import (
    MaintenanceStatus,
    ProjectActivity,
    ToolCompatibility,
    ToolExecutionType,
    ToolKnowledge,
    ToolMetadata,
)
from hunterx.domain.tool_mastery import ToolMasterProfile, ToolSupportLevel


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Compact declarative profile for one arsenal tool."""

    tool_id: str
    display_name: str
    vendor: str
    project_url: str
    license: str
    category: str
    subcategory: str
    description: str
    capabilities: tuple[str, ...]
    version: str = "1.0.0"
    language: str = ""
    tags: tuple[str, ...] = ()
    support_level: ToolSupportLevel = ToolSupportLevel.KNOWLEDGE_ONLY
    targets: tuple[str, ...] = ()
    protocols: tuple[str, ...] = ()
    input_formats: tuple[str, ...] = ()
    output_formats: tuple[str, ...] = ()
    structured_formats: tuple[str, ...] = ()
    parser_id: str = ""
    normalizer_id: str = ""
    adapter_id: str = ""
    version_constraints: tuple[str, ...] = ()
    alternatives: tuple[str, ...] = ()
    complementary: tuple[str, ...] = ()
    predecessors: tuple[str, ...] = ()
    successors: tuple[str, ...] = ()
    safety_class: str = "passive"
    destructive: bool = False
    scope_requirements: str = ""
    resource_requirements: str = ""
    rate_limits: str = ""
    false_positives: tuple[str, ...] = ()
    false_negatives: tuple[str, ...] = ()
    error_indicators: tuple[str, ...] = ()
    warning_indicators: tuple[str, ...] = ()
    partial_indicators: tuple[str, ...] = ()
    operational_knowledge: tuple[str, ...] = ()
    execution_type: ToolExecutionType = ToolExecutionType.BINARY
    package_manager: str = ""
    container_available: bool = False
    binary_available: bool = False


#: Adapter-backed tools (Sprint 034.5) whose arsenal spec predates the adapter.
#: key → (adapter_id, parser_id, normalizer_id, support_level). This keeps the
#: authoritative arsenal aligned with the real execution registry.
_ADAPTER_UPGRADES: dict[str, tuple[str, str, str, ToolSupportLevel]] = {
    "massdns": ("hunterx.tools.dns.massdns:MassdnsAdapter", "dns-json", "dns-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "shuffledns": ("hunterx.tools.dns.shuffledns:ShufflednsAdapter", "dns-json", "dns-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "rustscan": ("hunterx.tools.livehost.rustscan:RustScanAdapter", "live-observations", "live-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "gospider": ("hunterx.tools.web.url_discovery:GospiderAdapter", "url-jsonl", "url-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "hakrawler": ("hunterx.tools.web.url_discovery:HakrawlerAdapter", "url-text", "url-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "gau": ("hunterx.tools.web.url_discovery:GauAdapter", "url-text", "url-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "waybackurls": ("hunterx.tools.web.url_discovery:WaybackurlsAdapter", "url-text", "url-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "urlfinder": ("hunterx.tools.web.url_discovery:UrlfinderAdapter", "url-text", "url-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "gobuster": ("hunterx.tools.content.bruteforcers:GobusterAdapter", "content-jsonl", "content-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "feroxbuster": ("hunterx.tools.content.bruteforcers:FeroxbusterAdapter", "content-jsonl", "content-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "dirsearch": ("hunterx.tools.content.bruteforcers:DirsearchAdapter", "content-json", "content-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "arjun": ("hunterx.tools.parameter.adapters:ArjunAdapter", "parameter-json", "parameter-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "paramspider": ("hunterx.tools.parameter.adapters:ParamspiderAdapter", "parameter-text", "parameter-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "kiterunner": ("hunterx.tools.parameter.adapters:KiterunnerAdapter", "parameter-jsonl", "parameter-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "linkfinder": ("hunterx.tools.javascript.external:LinkFinderAdapter", "js-endpoints", "js-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "secretfinder": ("hunterx.tools.javascript.external:SecretFinderAdapter", "js-secrets", "js-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "xnlinkfinder": ("hunterx.tools.javascript.external:XnLinkFinderAdapter", "js-endpoints", "js-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "dalfox": ("hunterx.tools.vuln.injection:DalfoxAdapter", "candidate-json", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "xssstrike": ("hunterx.tools.vuln.injection:XSStrikeAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "sqlmap": ("hunterx.tools.vuln.injection:SQLmapAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "ghauri": ("hunterx.tools.vuln.injection:GhauriAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "commix": ("hunterx.tools.vuln.injection:CommixAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "tplmap": ("hunterx.tools.vuln.injection:TplmapAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "sstimap": ("hunterx.tools.vuln.injection:SSTImapAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "xxeinjector": ("hunterx.tools.vuln.injection:XXEinjectorAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "interactsh": ("hunterx.tools.vuln.injection:InteractshAdapter", "candidate-text", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "graphqlmap": ("hunterx.tools.api.graphql_binaries:GraphQLmapAdapter", "graphql-text", "api-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "inql": ("hunterx.tools.api.graphql_binaries:InQLAdapter", "graphql-text", "api-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "trufflehog": ("hunterx.tools.secrets.trufflehog:TrufflehogAdapter", "secrets-jsonl", "secret-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "semgrep": ("hunterx.tools.sast.semgrep:SemgrepAdapter", "candidate-json", "vulnerability-candidate-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "zap": ("hunterx.tools.proxy.adapters:ZapAdapter", "proxy-text", "proxy-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "mitmproxy": ("hunterx.tools.proxy.adapters:MitmproxyAdapter", "proxy-text", "proxy-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "metasploit": ("hunterx.tools.exploit.adapters:MetasploitAdapter", "exploit-text", "exploit-normalizer", ToolSupportLevel.EXECUTION_ONLY),
    "searchsploit": ("hunterx.tools.exploit.adapters:SearchsploitAdapter", "exploit-json", "exploit-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "exploitdb": ("hunterx.tools.exploit.adapters:ExploitdbAdapter", "exploit-json", "exploit-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "payloadsallthethings": ("hunterx.tools.knowledge.adapters:PayloadsAllTheThingsAdapter", "dataset-json", "dataset-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "seclists": ("hunterx.tools.knowledge.adapters:SeclistsAdapter", "dataset-json", "dataset-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
    "fuzzdb": ("hunterx.tools.knowledge.adapters:FuzzdbAdapter", "dataset-json", "dataset-normalizer", ToolSupportLevel.PARTIAL_SUPPORT),
}


def build_profile(spec: ToolSpec) -> ToolMasterProfile:
    """Expand a compact :class:`ToolSpec` into a full :class:`ToolMasterProfile`."""
    metadata = ToolMetadata(
        tool_id=spec.tool_id,
        display_name=spec.display_name,
        vendor=spec.vendor,
        project_url=spec.project_url,
        license=spec.license,
        category=spec.category,
        subcategory=spec.subcategory,
        version=spec.version,
        platforms=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        language=spec.language,
        execution_type=spec.execution_type,
        package_manager=spec.package_manager,
        container_available=spec.container_available,
        binary_available=spec.binary_available,
        maintenance_status=MaintenanceStatus.ACTIVE,
        project_activity=ProjectActivity.HIGH,
        community_score=_community_score(spec),
        description=spec.description,
        tags=spec.tags,
    )
    knowledge = ToolKnowledge(
        tool_id=spec.tool_id,
        canonical_name=spec.display_name,
        purpose=spec.description,
        capabilities=spec.capabilities,
        supported_assessments=(spec.category,),
        supported_mission_profiles=("bug-bounty", "pentest", "red-team"),
        limitations=_limitations(spec),
        known_issues=(),
        alternative_tools=spec.alternatives,
        recommended_usage=_recommended_usage(spec),
        common_mistakes=_common_mistakes(spec),
        supported_targets=spec.targets,
        supported_protocols=spec.protocols,
        parser_id=spec.parser_id,
        normalizer_id=spec.normalizer_id,
        adapter_id=spec.adapter_id,
        version_constraints=spec.version_constraints,
        known_false_positives=spec.false_positives,
        known_false_negatives=spec.false_negatives,
        provenance={"source": "sprint-025", "category": spec.category},
        knowledge_version="1.0.0",
    )
    compatibility = ToolCompatibility(
        tool_id=spec.tool_id,
        os=("linux", "windows", "darwin"),
        architectures=("amd64", "arm64"),
        docker=spec.container_available,
        native=spec.binary_available or spec.execution_type is ToolExecutionType.PIP,
        cloud=spec.category in ("cloud", "container"),
        air_gapped=False,
    )
    profile = ToolMasterProfile(
        tool_id=spec.tool_id,
        metadata=metadata,
        knowledge=knowledge,
        support_level=spec.support_level,
        compatibility=compatibility,
        capability_ids=spec.capabilities,
        supported_targets=spec.targets,
        supported_protocols=spec.protocols,
        input_formats=spec.input_formats,
        output_formats=spec.output_formats,
        structured_output_formats=spec.structured_formats,
        error_indicators=spec.error_indicators,
        warning_indicators=spec.warning_indicators,
        partial_result_indicators=spec.partial_indicators,
        false_positive_risks=spec.false_positives,
        false_negative_risks=spec.false_negatives,
        version_constraints=spec.version_constraints,
        parser_id=spec.parser_id,
        normalizer_id=spec.normalizer_id,
        adapter_id=spec.adapter_id,
        recommended_predecessors=spec.predecessors,
        recommended_successors=spec.successors,
        alternative_tools=spec.alternatives,
        complementary_tools=spec.complementary,
        safety_class=spec.safety_class,
        destructive=spec.destructive,
        scope_requirements=spec.scope_requirements,
        resource_requirements=spec.resource_requirements,
        rate_limits=spec.rate_limits,
        operational_knowledge=spec.operational_knowledge,
        provenance={"source": "sprint-025", "category": spec.category},
    )
    upgrade = _ADAPTER_UPGRADES.get(spec.tool_id)
    if upgrade is not None:
        adapter_id, parser_id, normalizer_id, support_level = upgrade
        profile = replace(
            profile,
            adapter_id=adapter_id,
            parser_id=parser_id,
            normalizer_id=normalizer_id,
            support_level=support_level,
        )
    return profile


def register_specs(registry, specs: list[ToolSpec]) -> None:
    """Register every compact spec as a master profile."""
    for spec in specs:
        registry.register(build_profile(spec))


def _community_score(spec: ToolSpec) -> float:
    score = {"amass": 95.0, "subfinder": 95.0, "nuclei": 95.0, "sqlmap": 95.0, "nmap": 95.0}
    return score.get(spec.tool_id, 70.0)


def _limitations(spec: ToolSpec) -> tuple[str, ...]:
    if spec.support_level is ToolSupportLevel.KNOWLEDGE_ONLY:
        return (
            "HunterX has operational knowledge but no integrated adapter/parser yet.",
            "Output must be treated as untrusted data pending integration.",
        )
    if spec.support_level is ToolSupportLevel.EXECUTION_ONLY:
        return ("HunterX can execute this tool but parsing/normalization is not integrated.",)
    return ("Tool results are observations; validation is required before a finding.",)


def _recommended_usage(spec: ToolSpec) -> tuple[str, ...]:
    return (
        f"Use {spec.tool_id} only against in-scope targets.",
        "Validate candidates before promoting them to findings.",
    )


def _common_mistakes(spec: ToolSpec) -> tuple[str, ...]:
    return (
        "Treating raw tool output as proof.",
        "Running without confirming scope and authorization.",
    )
