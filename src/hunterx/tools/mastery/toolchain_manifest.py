# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Full toolchain capability manifest (Sprint 031).

Generates ``capabilities/full-toolchain-intelligence.json`` — the ratified
manifest that lists every integrated tool and its capabilities, the canonical
capability catalog, per-capability toolchain strategies, knowledge sources,
typed events and interfaces. Generated from the authoritative arsenal so it
never drifts from reality.
"""

from __future__ import annotations

import json
from typing import Any

from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.mastery.knowledge_fixtures import ToolKnowledgeFixtureRegistry

#: Major capability → capability-id family used for strategy synthesis.
_STRATEGY_CAPABILITIES = {
    "subdomain-discovery": ("subdomain-discovery",),
    "dns-records": ("dns-records",),
    "port-scanning": ("port-scanning",),
    "http-probing": ("http-enumeration",),
    "technology-detection": ("technology-detection",),
    "web-crawling": ("web-crawling",),
    "directory-discovery": ("directory-discovery",),
    "parameter-discovery": ("parameter-discovery",),
    "javascript-analysis": ("javascript-analysis",),
    "vulnerability-scan": ("vulnerability-scan", "web-vulnerability-detection"),
    "xss-detection": ("xss-detection", "xss-discovery"),
    "sqli-detection": ("sqli-detection", "sql-injection-detection"),
    "command-injection": ("command-injection",),
    "oob-testing": ("oob-callback",),
    "ssti-detection": ("ssti-detection",),
    "xxe-detection": ("xxe-detection",),
    "graphql-testing": ("graphql-testing",),
    "secrets-detection": ("secrets-detection", "secret-discovery"),
    "static-analysis": ("static-analysis", "sast"),
    "proxy-inspection": ("proxy-inspection",),
    "exploit-development": ("exploit-development", "exploit-research"),
    "exploit-intelligence": ("exploit-research", "cve-research"),
    "payload-intelligence": ("payload-intelligence", "payload-generation"),
    "wordlist-provider": ("wordlist-provider",),
}

#: Canonical events exposed by the toolchain.
_TOOLCHAIN_EVENTS = (
    "tool.execution.started",
    "tool.execution.completed",
    "tool.execution.failed",
    "tool.output.received",
    "tool.output.parsed",
    "tool.output.normalized",
    "tool.evidence.extracted",
    "tool.observation.created",
    "tool.result.contradiction",
    "tool.health.failed",
    "tool.version.detected",
    "tool.recommendation.created",
)

#: CLI and API interfaces exposed by the toolchain.
_CLI_COMMANDS = (
    "hunterx tools list",
    "hunterx tools show <tool>",
    "hunterx tools capabilities [<tool>]",
    "hunterx tools health [<tool>]",
    "hunterx tools versions [<tool>]",
    "hunterx tools execute <tool> <target>",
    "hunterx tools inspect-result <execution_id>",
    "hunterx tools parse <tool> --raw <output|@file>",
    "hunterx tools normalize <tool> --records <json>",
    "hunterx tools chain <objective> --capabilities a,b,c",
    "hunterx tools recommend <capability>",
)

_API_ENDPOINTS = (
    "GET /tools",
    "GET /tools/{tool_id}",
    "GET /tools/{tool_id}/capabilities",
    "GET /tools/{tool_id}/health",
    "GET /tools/{tool_id}/versions",
    "GET /tools/{tool_id}/requirements",
    "GET /tools/{tool_id}/provenance",
    "GET /tools/capabilities",
    "GET /tools/recommend/{capability_id}",
    "POST /tools/chain",
    "POST /tools/execute",
    "GET /tools/executions/{execution_id}/status",
    "GET /tools/executions/{execution_id}/output",
    "GET /tools/executions/{execution_id}/result",
    "POST /tools/parse",
    "POST /tools/normalize",
)


def build_toolchain_manifest(mastery: ToolMasteryAPI | None = None) -> dict[str, Any]:
    """Build the full toolchain intelligence manifest."""
    mastery = mastery or ToolMasteryAPI()
    registry = ToolKnowledgeFixtureRegistry(mastery.registry, mastery.relationship_graph, mastery.dataset_registry)
    fixtures = registry.fixtures()

    tools: dict[str, dict[str, Any]] = {}
    for fixture in fixtures:
        identity = fixture["identity"]
        tool_id = identity["tool_id"]
        tools[tool_id] = {
            "name": identity["display_name"],
            "category": fixture["category"],
            "subcategory": fixture["subcategory"],
            "version": identity["version"],
            "support_level": fixture["support_level"],
            "capabilities": fixture["capabilities"],
            "targets": fixture["inputs"]["targets"],
            "output_formats": fixture["outputs"]["formats"],
            "parser": fixture["parser"]["parser_id"],
            "normalizer": fixture["normalizer"]["normalizer_id"],
            "adapter": fixture["version_information"]["adapter_id"],
            "alternatives": fixture["dependencies"]["alternatives"],
            "complementary": fixture["dependencies"]["complementary"],
            "follow_up": fixture["follow_up"]["next_tools"],
        }

    vocabulary = mastery.tip.vocabulary
    strategies: dict[str, dict[str, Any]] = {}
    for name, capability_ids in _STRATEGY_CAPABILITIES.items():
        canonical_family = {vocabulary.canonical(item) for item in capability_ids}
        providers: list[str] = []
        for fixture in fixtures:
            tool_capabilities = {vocabulary.canonical(item) for item in fixture["capabilities"]}
            if canonical_family & tool_capabilities:
                providers.append(fixture["identity"]["tool_id"])
        recommendations = mastery.tip.recommend(name)
        fallbacks: list[str] = []
        for rec in recommendations:
            if rec.kind.value in ("fallback", "alternative") and rec.tool_id not in fallbacks:
                fallbacks.append(rec.tool_id)
        strategies[name] = {
            "capability": name,
            "primary": providers[0] if providers else "",
            "providers": providers[:6],
            "fallbacks": fallbacks[:4],
            "complementary": [
                tool_id
                for tool_id in providers[1:6]
                if tool_id not in (providers[:1] if providers else [])
            ][:4],
        }

    knowledge_sources = [
        {"tool_id": "payloadsallthethings", "role": "payload knowledge base", "consumed_by": ["dalfox", "sqlmap", "commix", "sstimap", "xxeinjector"]},
        {"tool_id": "seclists", "role": "wordlist provider", "consumed_by": ["ffuf", "gobuster", "feroxbuster", "dirsearch", "massdns", "shuffledns"]},
        {"tool_id": "fuzzdb", "role": "attack/response pattern dictionaries", "consumed_by": ["ffuf", "dalfox", "sqlmap", "commix", "sstimap"]},
    ]

    return {
        "capability": "full-toolchain-intelligence",
        "name": "Full Toolchain Integration & Professional Tool Intelligence",
        "version": "1.0.0",
        "wave": 16,
        "status": "ratified",
        "description": (
            "HunterX understands the complete authorized offensive-security toolchain: "
            "WHAT each tool does, WHEN to use it, WHAT it requires, HOW to invoke it "
            "safely within scope, WHAT its output means and WHAT its output does NOT "
            "prove. Structured execution, versioned parsers/normalizers, evidence "
            "extraction, cross-tool correlation, fallback strategies and canonical "
            "capability vocabulary."
        ),
        "tool_count": len(tools),
        "tools": tools,
        "capability_catalog": sorted(mastery.tip.capabilities()),
        "toolchains": strategies,
        "knowledge_sources": knowledge_sources,
        "events": list(_TOOLCHAIN_EVENTS),
        "interfaces": {
            "cli": list(_CLI_COMMANDS),
            "api": list(_API_ENDPOINTS),
        },
        "architecture": {
            "domain": "hunterx.domain.tool_intelligence",
            "application": "hunterx.application.toolchain.ToolchainService",
            "sdk": "hunterx.tools.sdk",
            "intelligence": "hunterx.tools.intelligence",
            "mastery": "hunterx.tools.mastery",
            "cli": "hunterx.cli.commands (hunterx tools)",
            "api": "hunterx.api.tools",
            "documentation": "docs/v7-full-toolchain-intelligence.md",
        },
        "testing": [
            "unit: tests/unit/test_toolchain_service.py",
            "unit: tests/unit/test_toolchain_events.py",
            "unit: tests/unit/test_tool_knowledge_fixtures.py",
            "unit: tests/unit/test_tool_capability_vocabulary.py",
            "unit: tests/unit/test_toolchain_cli.py",
            "component: tests/component/test_toolchain_api.py",
            "golden: tests/golden/test_toolchain_golden.py",
            "acceptance: tests/acceptance/test_full_toolchain_acceptance.py",
            "security: tests/security/test_toolchain_security.py",
            "performance: tests/performance/test_toolchain_performance.py",
            "architecture: tests/architecture/test_tool_layering.py",
        ],
        "manifest_version": "1.0.0",
    }


def export_manifest(path: str, mastery: ToolMasteryAPI | None = None) -> None:
    """Write the full toolchain manifest to ``path`` (JSON)."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(build_toolchain_manifest(mastery), handle, indent=2)
        handle.write("\n")


__all__ = ["build_toolchain_manifest", "export_manifest"]
