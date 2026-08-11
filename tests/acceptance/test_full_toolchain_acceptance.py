# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the Sprint 031 Full Toolchain Integration.

End-to-end scenarios against the composed platform: the toolchain catalog,
knowledge contracts, selection, chain planning, fallback strategies,
cross-tool evidence correlation, contradiction preservation and target
intelligence updates — without executing any external binary.
"""

from __future__ import annotations

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    EvidenceStrength,
    ToolSelectionCriteria,
)
from hunterx.platform import build_platform


def _observation(
    observation_id: str,
    tool_id: str,
    kind: str,
    value: str,
    correlation_key: str,
    *,
    confidence: float = 1.0,
    target: str = "example.com",
) -> CanonicalObservation:
    return CanonicalObservation(
        observation_id=observation_id,
        target_id=target,
        tool_id=tool_id,
        observation_kind=kind,
        value=value,
        normalized_value=value,
        correlation_key=correlation_key,
        confidence=confidence,
    )


def _platform():
    return build_platform()


def test_toolchain_catalog_covers_approved_arsenal() -> None:
    platform = _platform()
    tools = {tool["tool_id"] for tool in platform.toolchain_service.list_tools()}
    for tool_id in ("subfinder", "amass", "dnsx", "naabu", "nmap", "httpx", "katana", "ffuf", "nuclei", "gitleaks"):
        assert tool_id in tools, f"missing {tool_id}"


def test_knowledge_sources_registered() -> None:
    platform = _platform()
    tools = {tool["tool_id"] for tool in platform.toolchain_service.list_tools()}
    assert {"payloadsallthethings", "seclists", "fuzzdb"}.issubset(tools)


def test_recon_chain_planning_uses_fallbacks() -> None:
    platform = _platform()
    strategy = platform.toolchain_service.strategies("subdomain-discovery")
    assert strategy["primary"] == "subfinder"
    assert "amass" in strategy["fallbacks"]
    assert strategy["merge_policy"] == "deduplicate"


def test_subdomain_results_deduplicated_across_tools() -> None:
    platform = _platform()
    subfinder = _observation("obs-1", "subfinder", "domain", "api.example.com", "sub:api.example.com")
    amass = _observation("obs-2", "amass", "domain", "api.example.com", "sub:api.example.com", confidence=0.9)
    chains = platform.tip.correlate([subfinder, amass])
    matching = [chain for chain in chains if chain.correlation_key == "sub:api.example.com"]
    assert matching
    assert set(matching[0].tools) == {"amass", "subfinder"}
    assert matching[0].strength is EvidenceStrength.BEHAVIORAL


def test_recon_to_probe_to_scan_chain_correlates() -> None:
    platform = _platform()
    subdomain = _observation("obs-1", "subfinder", "domain", "api.example.com", "sub:api.example.com")
    resolved = _observation("obs-2", "dnsx", "domain", "api.example.com", "sub:api.example.com")
    probe = _observation("obs-3", "httpx", "url", "https://api.example.com", "url:https://api.example.com")
    candidate = _observation(
        "obs-4",
        "nuclei",
        "vulnerability",
        "CVE-2021-0001",
        "vuln:api.example.com:CVE-2021-0001",
        confidence=0.6,
    )
    chains = platform.tip.correlate([subdomain, resolved, probe, candidate])
    keys = {chain.correlation_key for chain in chains}
    assert "sub:api.example.com" in keys
    assert "url:https://api.example.com" in keys
    assert "vuln:api.example.com:CVE-2021-0001" in keys


def test_tool_contradiction_is_preserved_not_averaged() -> None:
    platform = _platform()
    nmap_open = _observation("obs-1", "nmap", "service", "open", "svc:10.0.0.1:443", confidence=0.95)
    naabu_closed = _observation("obs-2", "naabu", "service", "closed", "svc:10.0.0.1:443", confidence=0.95)
    detected = platform.tip.layer.conflicts([nmap_open, naabu_closed])
    assert detected
    assert detected[0].correlation_key == "svc:10.0.0.1:443"
    assert set(detected[0].tools) == {"nmap", "naabu"}
    # Both values preserved — never averaged.
    values = {obs.normalized_value for obs in detected[0].observations}
    assert values == {"open", "closed"}


def test_selection_ranks_tools_for_capability() -> None:
    platform = _platform()
    selections = platform.tip.select_intelligence(
        ToolSelectionCriteria(required_capabilities=("subdomain-discovery",), require_installed=False)
    )
    assert selections
    assert selections[0].tool_id == "subfinder"
    assert "amass" in selections[0].alternatives


def test_record_execution_updates_target_intelligence() -> None:
    platform = _platform()
    observation = _observation("obs-1", "nmap", "port", "443", "port:10.0.0.1:443")
    platform.tip.record_execution(
        tool_id="nmap",
        target="10.0.0.1",
        tool_version="7.94",
        observations=(observation,),
        duration_ms=42,
    )
    snapshot = platform.tip.target_snapshot("10.0.0.1")
    assert any(record.tool_id == "nmap" for record in snapshot.execution_history)


def test_execution_profile_and_offline_replay() -> None:
    platform = _platform()
    parsed = platform.toolchain_service.parse("subfinder", '{"host": "api.example.com", "source": "crt.sh"}')
    assert parsed["count"] >= 1
    first = parsed["records"][0]
    assert first.get("name") == "api.example.com" or first.get("host") == "api.example.com"


def test_recommendation_explains_selection() -> None:
    platform = _platform()
    recommendations = platform.toolchain_service.recommend("sql-injection-detection")
    assert recommendations
    best = recommendations[0]
    assert best["tool_id"] == "sqlmap"
    assert best["kind"] == "best"
    assert best["reason"]
