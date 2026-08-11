# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool knowledge fixtures (Sprint 031).

Every integrated tool must have a structured knowledge contract — WHAT it
does, WHEN to use it, WHAT it requires, WHAT its output means, WHAT its output
does NOT prove, WHAT evidence/observations/findings it can contribute and WHAT
follow-up actions are appropriate.

This registry synthesizes that contract for every arsenal tool from the
authoritative mastery profiles, relationship graph and dataset registry. It
never executes a tool and never claims more than the profile supports.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from hunterx.domain.tool_mastery import (
    ToolDataset,
    ToolMasterProfile,
    ToolRelationshipKind,
    ToolSupportLevel,
)
from hunterx.tools.mastery.registry import ToolMasteryRegistry
from hunterx.tools.mastery.relationships import ToolRelationshipGraph

#: Canonical capability → observation kind mapping (Section 22/13).
_CAPABILITY_OBSERVATION_KIND: dict[str, str] = {
    "subdomain-discovery": "domain",
    "subdomain-enumeration": "domain",
    "domain-enumeration": "domain",
    "dns-enumeration": "domain",
    "host-discovery": "ip",
    "dns-records": "domain",
    "dns-resolution": "domain",
    "dnssec": "domain",
    "brute-force-dns": "domain",
    "wildcard-detection": "domain",
    "port-scanning": "port",
    "port-discovery": "port",
    "service-fingerprint": "service",
    "service-discovery": "service",
    "os-detection": "service",
    "version-detection": "version",
    "ssl-analysis": "certificate",
    "tls-analysis": "certificate",
    "certificate-lookup": "certificate",
    "certificate-enumeration": "certificate",
    "dns-history": "domain",
    "whois-lookup": "asset",
    "asn-enumeration": "asset",
    "osint": "asset",
    "http-enumeration": "path",
    "http-probing": "url",
    "technology-detection": "technology",
    "waf-detection": "technology",
    "web-server-analysis": "technology",
    "web-crawling": "url",
    "crawling": "url",
    "directory-discovery": "path",
    "file-enumeration": "path",
    "vhost-enumeration": "header",
    "parameter-discovery": "parameter",
    "get-parameter-discovery": "parameter",
    "post-parameter-discovery": "parameter",
    "historical-parameter-discovery": "parameter",
    "javascript-analysis": "path",
    "javascript-discovery": "path",
    "endpoint-discovery": "path",
    "endpoint-extraction": "path",
    "source-map-discovery": "path",
    "api-discovery": "parameter",
    "api-parameter-analysis": "parameter",
    "openapi-analysis": "parameter",
    "graphql-testing": "parameter",
    "graphql-analysis": "parameter",
    "graphql-introspection": "parameter",
    "vulnerability-scan": "vulnerability",
    "web-vulnerability-detection": "vulnerability",
    "network-vulnerability-detection": "vulnerability",
    "misconfiguration-detection": "vulnerability",
    "cve-detection": "cve",
    "cve-analysis": "cve",
    "vulnerability-mapping": "cve",
    "sqli-detection": "vulnerability",
    "sql-injection-detection": "vulnerability",
    "xss-detection": "vulnerability",
    "xss-discovery": "vulnerability",
    "ssti-detection": "vulnerability",
    "command-injection": "vulnerability",
    "command-injection-detection": "vulnerability",
    "xxe-detection": "vulnerability",
    "oob-testing": "evidence",
    "oob-callback": "evidence",
    "dns-callback": "evidence",
    "http-callback": "evidence",
    "smtp-callback": "evidence",
    "interaction-correlation": "evidence",
    "secrets-detection": "other",
    "secrets-scan": "other",
    "secret-discovery": "other",
    "credential-discovery": "other",
    "token-discovery": "other",
    "key-discovery": "other",
    "static-analysis": "other",
    "sast": "other",
    "code-pattern-analysis": "other",
    "code-flow-analysis": "other",
    "taint-analysis": "other",
    "proxy-inspection": "header",
    "http-interception": "header",
    "traffic-capture": "header",
    "exploit-intelligence": "cve",
    "exploit-research": "cve",
    "cve-research": "cve",
    "exploit-development": "vulnerability",
    "cloud-assessment": "cloud-resource",
    "cloud-misconfiguration": "cloud-resource",
    "cloud-permission-audit": "cloud-resource",
    "cloud-asset-discovery": "cloud-resource",
    "container-assessment": "cloud-resource",
    "image-scan": "vulnerability",
    "container-analysis": "cloud-resource",
    "payload-generation": "other",
    "payload-intelligence": "other",
    "attack-patterns": "other",
    "response-patterns": "other",
    "wordlist": "other",
    "wordlist-provider": "other",
    "authentication-analysis": "header",
    "jwt-analysis": "token",
    "session-management": "header",
}

#: Canonical capability → evidence type mapping (Section 15).
_CAPABILITY_EVIDENCE_TYPE: dict[str, str] = {
    "subdomain-discovery": "dns-observation",
    "subdomain-enumeration": "dns-observation",
    "domain-enumeration": "dns-observation",
    "dns-enumeration": "dns-observation",
    "host-discovery": "dns-observation",
    "dns-records": "dns-observation",
    "dns-resolution": "dns-observation",
    "brute-force-dns": "dns-observation",
    "port-scanning": "port-observation",
    "port-discovery": "port-observation",
    "service-fingerprint": "service-observation",
    "service-discovery": "service-observation",
    "os-detection": "service-observation",
    "technology-detection": "technology-observation",
    "http-probing": "http-observation",
    "http-enumeration": "http-observation",
    "directory-discovery": "http-observation",
    "file-enumeration": "http-observation",
    "parameter-discovery": "parameter-observation",
    "get-parameter-discovery": "parameter-observation",
    "post-parameter-discovery": "parameter-observation",
    "javascript-analysis": "endpoint-observation",
    "endpoint-extraction": "endpoint-observation",
    "api-discovery": "endpoint-observation",
    "graphql-introspection": "graphql-observation",
    "vulnerability-scan": "scanner-candidate",
    "web-vulnerability-detection": "scanner-candidate",
    "network-vulnerability-detection": "scanner-candidate",
    "misconfiguration-detection": "scanner-candidate",
    "sqli-detection": "sqli-candidate",
    "sql-injection-detection": "sqli-candidate",
    "xss-detection": "xss-candidate",
    "xss-discovery": "xss-candidate",
    "ssti-detection": "ssti-candidate",
    "command-injection": "command-injection-candidate",
    "command-injection-detection": "command-injection-candidate",
    "xxe-detection": "xxe-candidate",
    "oob-testing": "oob-callback",
    "oob-callback": "oob-callback",
    "interaction-correlation": "oob-callback",
    "secrets-detection": "secret-candidate",
    "secrets-scan": "secret-candidate",
    "secret-discovery": "secret-candidate",
    "credential-discovery": "secret-candidate",
    "token-discovery": "secret-candidate",
    "key-discovery": "secret-candidate",
    "static-analysis": "code-finding-candidate",
    "sast": "code-finding-candidate",
    "code-pattern-analysis": "code-finding-candidate",
    "code-flow-analysis": "code-finding-candidate",
    "exploit-intelligence": "exploit-reference",
    "exploit-research": "exploit-reference",
    "cve-research": "exploit-reference",
    "image-scan": "vulnerability-candidate",
    "payload-intelligence": "payload-reference",
    "attack-patterns": "attack-pattern-reference",
    "response-patterns": "response-pattern-reference",
    "wordlist-provider": "wordlist-reference",
}

#: Capabilities that inherently require validation before a finding.
_VALIDATION_REQUIRED = {
    "sqli-detection",
    "sql-injection-detection",
    "xss-detection",
    "xss-discovery",
    "ssti-detection",
    "command-injection",
    "command-injection-detection",
    "xxe-detection",
    "vulnerability-scan",
    "web-vulnerability-detection",
    "network-vulnerability-detection",
    "misconfiguration-detection",
    "oob-testing",
    "oob-callback",
}

#: Canonical exit-code knowledge for well-known families.
_DEFAULT_EXIT_CODES: tuple[str, ...] = (
    "0: completed",
    "1: completed with warnings or no findings",
    "2: error",
)


class ToolKnowledgeFixtureRegistry:
    """Produce structured knowledge contracts for every arsenal tool.

    A fixture is a plain mapping (JSON-safe) so the CLI, API, documentation and
    golden tests consume the same shape.
    """

    def __init__(
        self,
        registry: ToolMasteryRegistry,
        relationships: ToolRelationshipGraph | None = None,
        datasets: Any = None,
    ) -> None:
        self._registry = registry
        self._relationships = relationships or ToolRelationshipGraph()
        self._datasets = datasets

    def get(self, tool_id: str) -> dict[str, Any] | None:
        """Return the knowledge fixture for ``tool_id`` or ``None``."""
        profile = self._registry.get(tool_id)
        if profile is None:
            return None
        return _build_fixture(profile, self._relationships, self._datasets)

    def fixtures(self) -> list[dict[str, Any]]:
        """Return knowledge fixtures for every registered arsenal tool."""
        return [_build_fixture(profile, self._relationships, self._datasets) for profile in self._registry.list()]

    def count(self) -> int:
        """Return the number of arsenal tools with fixtures."""
        return len(self._registry.list())


def _build_fixture(
    profile: ToolMasterProfile,
    relationships: ToolRelationshipGraph,
    datasets: Any,
) -> dict[str, Any]:
    """Expand a master profile into the full knowledge contract."""
    tool_id = profile.tool_id
    metadata = profile.metadata
    knowledge = profile.knowledge
    edges = relationships.edges_for(tool_id)
    follow_ups = _follow_ups(relationships, tool_id)
    return {
        "identity": {
            "tool_id": tool_id,
            "display_name": metadata.display_name,
            "vendor": metadata.vendor,
            "project_url": metadata.project_url,
            "license": metadata.license,
            "version": metadata.version,
            "category": metadata.category,
            "subcategory": metadata.subcategory,
            "tags": list(metadata.tags),
        },
        "description": metadata.description,
        "category": metadata.category,
        "subcategory": metadata.subcategory,
        "support_level": profile.support_level.value,
        "capabilities": list(profile.capability_ids),
        "inputs": {
            "targets": list(profile.supported_targets or knowledge.supported_targets),
            "protocols": list(profile.supported_protocols or knowledge.supported_protocols),
            "required": list(knowledge.inputs.required),
            "optional": list(knowledge.inputs.optional),
            "accepts": list(knowledge.inputs.accepts),
        },
        "outputs": {
            "formats": list(profile.output_formats or knowledge.outputs.formats),
            "structured_formats": list(profile.structured_output_formats),
            "input_formats": list(profile.input_formats),
        },
        "supported_formats": list(dict.fromkeys([*profile.output_formats, *profile.structured_output_formats])),
        "authentication_requirements": knowledge.authentication_requirements,
        "privileges_required": knowledge.privileges_required,
        "network_requirements": _network_requirements(profile),
        "os_requirements": list(metadata.platforms),
        "dependencies": {
            "predecessors": list(profile.recommended_predecessors),
            "complementary": list(profile.complementary_tools),
            "alternatives": list(profile.alternative_tools),
        },
        "version_information": {
            "known_version": metadata.version,
            "constraints": list(profile.version_constraints),
            "known_issues": list(profile.known_version_issues),
            "parser_id": profile.parser_id,
            "normalizer_id": profile.normalizer_id,
            "adapter_id": profile.adapter_id,
        },
        "scope_considerations": {
            "scope_requirements": profile.scope_requirements,
            "safety_class": profile.safety_class,
            "destructive": profile.destructive,
        },
        "resource_requirements": profile.resource_requirements,
        "rate_limits": profile.rate_limits,
        "safe_defaults": list(knowledge.recommended_usage),
        "dangerous_operations": _dangerous_operations(profile),
        "limitations": list(knowledge.limitations or profile.false_negative_risks),
        "known_failure_modes": {
            "error_indicators": list(profile.error_indicators),
            "warning_indicators": list(profile.warning_indicators),
            "partial_indicators": list(profile.partial_result_indicators),
        },
        "exit_codes": list(profile.exit_codes or _DEFAULT_EXIT_CODES),
        "parser": {
            "parser_id": profile.parser_id,
            "normalizer_id": profile.normalizer_id,
        },
        "normalizer": {
            "normalizer_id": profile.normalizer_id,
            "schema": "canonical-observation",
        },
        "evidence_mappings": _evidence_mappings(profile),
        "observation_mappings": _observation_mappings(profile),
        "follow_up": follow_ups,
        "examples": list(knowledge.examples),
        "operational_knowledge": list(profile.operational_knowledge),
        "false_positive_risks": list(profile.false_positive_risks or knowledge.known_false_positives),
        "false_negative_risks": list(profile.false_negative_risks or knowledge.known_false_negatives),
        "datasets": _dataset_refs(datasets, tool_id),
        "relationship_edges": [
            {
                "source": edge.source,
                "target": edge.target,
                "kind": edge.kind.value,
                "capability": edge.capability,
                "rationale": edge.rationale,
            }
            for edge in edges
        ],
        "provenance": dict(profile.provenance),
        "knowledge_version": knowledge.knowledge_version,
    }


def _follow_ups(relationships: ToolRelationshipGraph, tool_id: str) -> dict[str, list[str]]:
    """Return the appropriate follow-up actions for ``tool_id``."""
    return {
        "successors": relationships.successors(tool_id),
        "validates": relationships.validates(tool_id),
        "next_tools": relationships.next_tools(tool_id),
        "escalates_to": [
            target for edge in relationships.edges_for(tool_id)
            if edge.kind in (ToolRelationshipKind.ESCALATES_TO, ToolRelationshipKind.VALIDATES)
            for target in (edge.target,)
        ],
    }


def _evidence_mappings(profile: ToolMasterProfile) -> list[dict[str, Any]]:
    """Map each capability to canonical evidence semantics."""
    return [
        {
            "capability": capability,
            "observation_kind": _CAPABILITY_OBSERVATION_KIND.get(capability, "other"),
            "evidence_type": _CAPABILITY_EVIDENCE_TYPE.get(capability, "observation"),
            "requires_validation": capability in _VALIDATION_REQUIRED,
            "strength": "detection",
            "ceiling": 0.5,
        }
        for capability in profile.capability_ids
    ]


def _observation_mappings(profile: ToolMasterProfile) -> list[dict[str, Any]]:
    return [
        {
            "capability": capability,
            "observation_kind": _CAPABILITY_OBSERVATION_KIND.get(capability, "other"),
        }
        for capability in profile.capability_ids
    ]


def _network_requirements(profile: ToolMasterProfile) -> str:
    if profile.safety_class in ("active", "high-impact", "restricted"):
        return "outbound to target; callbacks require explicit OOB policy"
    if profile.support_level is ToolSupportLevel.KNOWLEDGE_ONLY:
        return "not executed by HunterX (knowledge-only)"
    return "outbound to target within scope"


def _dangerous_operations(profile: ToolMasterProfile) -> list[str]:
    if not profile.destructive:
        return []
    return [f"{profile.tool_id} can alter target state and must run under explicit authorization."]


def _dataset_refs(datasets: Any, tool_id: str) -> list[dict[str, Any]]:
    if datasets is None:
        return []
    compatible: list[ToolDataset] = []
    for dataset in datasets.list():
        if tool_id in dataset.compatibility:
            compatible.append(dataset)
    return [
        {
            "dataset_id": dataset.dataset_id,
            "name": dataset.name,
            "version": dataset.version,
            "category": dataset.category,
            "purpose": dataset.purpose,
            "safety_classification": dataset.safety_classification,
            "compatibility": list(dataset.compatibility),
        }
        for dataset in compatible
    ]


def dataset_fixture(dataset: ToolDataset) -> dict[str, Any]:
    """Return a JSON-safe fixture for a knowledge/payload dataset."""
    return asdict(dataset)
