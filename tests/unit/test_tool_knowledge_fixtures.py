# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Sprint 031 tool knowledge fixtures.

Every integrated tool must have a structured knowledge contract covering what
it does, when to use it, what it requires, what its output means and what its
output does NOT prove.
"""

from __future__ import annotations

import json

import pytest

from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.mastery.knowledge_fixtures import ToolKnowledgeFixtureRegistry

#: The approved Sprint 031 toolchain.
APPROVED_TOOLCHAIN = {
    "amass", "subfinder", "assetfinder", "findomain", "dnsx", "massdns",
    "shuffledns", "naabu", "nmap", "masscan", "rustscan", "httpx", "whatweb",
    "katana", "gospider", "hakrawler", "gau", "waybackurls", "urlfinder",
    "ffuf", "feroxbuster", "gobuster", "dirsearch", "arjun", "paramspider",
    "kiterunner", "linkfinder", "secretfinder", "xnlinkfinder", "nuclei",
    "dalfox", "xssstrike", "sqlmap", "ghauri", "commix", "interactsh",
    "tplmap", "sstimap", "xxeinjector", "graphqlmap", "inql", "gitleaks",
    "trufflehog", "semgrep", "zap", "mitmproxy", "metasploit", "searchsploit",
    "exploitdb", "payloadsallthethings", "seclists", "fuzzdb",
}


@pytest.fixture
def registry() -> ToolKnowledgeFixtureRegistry:
    mastery = ToolMasteryAPI()
    return ToolKnowledgeFixtureRegistry(mastery.registry, mastery.relationship_graph, mastery.dataset_registry)


def test_every_approved_tool_has_a_fixture(registry: ToolKnowledgeFixtureRegistry) -> None:
    known = {fixture["identity"]["tool_id"] for fixture in registry.fixtures()}
    assert APPROVED_TOOLCHAIN.issubset(known), APPROVED_TOOLCHAIN - known


def test_fixtures_are_json_safe(registry: ToolKnowledgeFixtureRegistry) -> None:
    for fixture in registry.fixtures():
        json.dumps(fixture)


def test_fixture_contains_full_knowledge_contract(registry: ToolKnowledgeFixtureRegistry) -> None:
    fixture = registry.get("nmap")
    assert fixture is not None
    for key in (
        "identity", "description", "category", "capabilities", "inputs", "outputs",
        "supported_formats", "version_information", "scope_considerations",
        "limitations", "known_failure_modes", "exit_codes", "parser", "normalizer",
        "evidence_mappings", "observation_mappings", "follow_up",
    ):
        assert key in fixture, f"missing '{key}' in nmap fixture"


def test_fixture_evidence_mappings_require_validation(registry: ToolKnowledgeFixtureRegistry) -> None:
    sqlmap = registry.get("sqlmap")
    assert sqlmap is not None
    mapping = next(
        m for m in sqlmap["evidence_mappings"]
        if m["capability"] == "sql-injection-detection"
    )
    assert mapping["requires_validation"] is True
    assert mapping["evidence_type"] == "sqli-candidate"


def test_knowledge_sources_have_follow_up_and_safe_scope(registry: ToolKnowledgeFixtureRegistry) -> None:
    payloads = registry.get("payloadsallthethings")
    assert payloads is not None
    assert payloads["follow_up"]["successors"]
    assert payloads["scope_considerations"]["safety_class"] == "passive"

    seclists = registry.get("seclists")
    assert seclists is not None
    assert "wordlist-provider" in seclists["capabilities"]


def test_recon_chain_fixtures_connect(registry: ToolKnowledgeFixtureRegistry) -> None:
    subfinder = registry.get("subfinder")
    assert subfinder is not None
    assert "httpx" in subfinder["follow_up"]["next_tools"]

    dnsx = registry.get("dnsx")
    assert dnsx is not None
    assert "httpx" in dnsx["follow_up"]["next_tools"]


def test_nuclei_candidates_are_not_confirmed_findings(registry: ToolKnowledgeFixtureRegistry) -> None:
    nuclei = registry.get("nuclei")
    assert nuclei is not None
    detection = next(
        m for m in nuclei["evidence_mappings"]
        if m["capability"] == "web-vulnerability-detection"
    )
    assert detection["requires_validation"] is True
