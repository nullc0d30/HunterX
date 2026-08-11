# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tool contract certification (Sprint 034.5).

Proves the gate requirement "every registered tool has a defined contract":
every tool in the certified registry exposes a consolidated machine-readable
contract covering identity, version, category, capabilities, requirements,
input schema, argument builder, scope model, execution profile, timeout,
resource limits, output formats, exit-code mapping, parser, normalizer,
artifact handling, error mapping, retry policy, evidence mapping and
downstream capabilities.
"""

from __future__ import annotations

import json

from hunterx.domain.tool_contract import ToolContract
from hunterx.platform import build_platform
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.mastery.contract import build_contract

#: The certified toolchain named in Sprint 034.5.
CERTIFIED_TOOLCHAIN = {
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

#: Minimum contract dimensions mandated by the sprint brief.
CONTRACT_DIMENSIONS = {
    "identity", "version", "category", "capabilities", "requirements",
    "input_schema", "argument_builder", "scope_model", "execution_profile",
    "timeout", "resource_limits", "output_formats", "exit_code_mapping",
    "parser", "normalizer", "artifact_handling", "error_mapping",
    "retry_policy", "evidence_mapping", "downstream_capabilities",
}


def _mastery() -> ToolMasteryAPI:
    return ToolMasteryAPI()


def test_every_arsenal_tool_has_a_complete_contract() -> None:
    mastery = _mastery()
    profiles = mastery.profiles()
    assert len(profiles) >= 92
    incomplete: list[tuple[str, tuple[str, ...]]] = []
    for profile in profiles:
        contract = build_contract(profile, mastery.relationship_graph)
        missing = contract.missing_dimensions()
        if missing:
            incomplete.append((profile.tool_id, missing))
    assert not incomplete, f"tools with missing contract dimensions: {incomplete}"


def test_certified_toolchain_all_present() -> None:
    mastery = _mastery()
    known = {profile.tool_id for profile in mastery.profiles()}
    missing = CERTIFIED_TOOLCHAIN - known
    assert not missing, f"certified tools missing from the arsenal: {missing}"


def test_contracts_are_json_serializable() -> None:
    mastery = _mastery()
    for profile in mastery.profiles():
        contract = build_contract(profile, mastery.relationship_graph).to_dict()
        json.dumps(contract)


def test_every_contract_dimension_populated() -> None:
    mastery = _mastery()
    for profile in mastery.profiles():
        contract = build_contract(profile, mastery.relationship_graph).to_dict()
        for dimension in CONTRACT_DIMENSIONS:
            assert contract.get(dimension) not in (None, "", [], {}), (
                f"{profile.tool_id}.{dimension} is empty"
            )


def test_contract_has_evidence_and_downstream_mapping() -> None:
    mastery = _mastery()
    for profile in mastery.profiles():
        contract = build_contract(profile, mastery.relationship_graph)
        assert contract.evidence_mapping, f"{profile.tool_id} has no evidence mapping"
        assert contract.downstream_capabilities, f"{profile.tool_id} has no downstream capabilities"


def test_contract_minimum_model_shape() -> None:
    contract = ToolContract(tool_id="nmap")
    assert contract.to_dict()["tool_id"] == "nmap"
    assert "missing_dimensions" in dir(contract)


def test_platform_exposes_contracts_for_every_registered_tool() -> None:
    platform = build_platform()
    service = platform.toolchain_service
    tools = {tool["tool_id"] for tool in service.list_tools()}
    contracts = {item["tool_id"] for item in service.contracts()}
    assert tools <= contracts, tools - contracts
    for tool_id in ("nmap", "subfinder", "sqlmap"):
        contract = service.contract(tool_id)
        for dimension in CONTRACT_DIMENSIONS:
            assert contract.get(dimension) not in (None, "", [], {}), f"{tool_id}.{dimension} empty"
