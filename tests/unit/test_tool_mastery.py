# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Sprint 025 Tool Mastery facade.

Covers the :class:`ToolMasteryAPI` facade: seeding the universal arsenal,
master-profile registry, relationship graph integrity, playbook catalog,
mission-aware selection, target history, coverage, datasets, version
awareness and the :class:`ToolMasteryPort` contract.
"""

from __future__ import annotations

from hunterx.domain.ports.tool_mastery import ToolMasteryPort
from hunterx.domain.tool_mastery import (
    ToolHistoryStatus,
    ToolPlaybookCategory,
    ToolSupportLevel,
)
from hunterx.tools.mastery.api import ToolMasteryAPI


def _mastery() -> ToolMasteryAPI:
    return ToolMasteryAPI()


# -- seeding -----------------------------------------------------------

def test_seeds_full_arsenal():
    mastery = _mastery()
    ids = mastery.tool_ids()
    assert len(ids) >= 80
    for expected in ("nuclei", "nmap", "subfinder", "ffuf", "sqlmap", "gitleaks", "interactsh"):
        assert expected in ids


def test_seeds_playbooks_datasets_relationships():
    mastery = _mastery()
    assert len(mastery.playbooks()) == 17
    assert len(mastery.datasets()) >= 10
    assert len(mastery.relationship_graph.edges) >= 50


def test_seed_is_idempotent():
    mastery = _mastery()
    first_count = len(mastery.tool_ids())
    mastery.seed_defaults()
    assert len(mastery.tool_ids()) == first_count


def test_relationship_references_resolve():
    mastery = _mastery()
    assert mastery.unknown_tool_refs() == []


# -- registry ----------------------------------------------------------

def test_get_profile_and_providers():
    mastery = _mastery()
    profile = mastery.get_profile("nuclei")
    assert profile is not None
    assert profile.metadata.tool_id == "nuclei"
    providers = mastery.providers_of("xss-validation")
    assert "dalfox" in providers


def test_by_support_level():
    mastery = _mastery()
    full = mastery.by_support_level(ToolSupportLevel.FULLY_SUPPORTED)
    assert "subfinder" in full
    assert "gitleaks" in full


def test_register_profile_replaces():
    mastery = _mastery()
    profile = mastery.get_profile("nuclei")
    mastery.register_profile(profile)
    assert mastery.get_profile("nuclei") is profile


# -- relationships -----------------------------------------------------

def test_relationship_queries():
    mastery = _mastery()
    assert "nuclei" in mastery.next_tools("httpx")
    assert "dalfox" in mastery.next_tools("nuclei")
    assert "httpx" in mastery.previous_tools("nuclei")
    assert "ghauri" in mastery.alternatives("sqlmap")
    assert mastery.relationships("nuclei")  # non-empty


# -- playbooks ---------------------------------------------------------

def test_playbooks_by_mission_and_category():
    mastery = _mastery()
    validation = mastery.playbooks_by_category(ToolPlaybookCategory.VALIDATION)
    assert len(validation) >= 5
    assert mastery.get_playbook("web-initial-recon") is not None
    by_mission = mastery.playbooks_by_mission("bug-bounty")
    assert any(p.playbook_id == "web-initial-recon" for p in by_mission)


# -- selection ---------------------------------------------------------

def test_selection_explainable_and_safety_ceilinged():
    mastery = _mastery()
    best = mastery.select_best("xss-validation", mission_type="bug-bounty")
    assert best.tool_id == "dalfox"
    assert best.required_capability == "xss-validation"
    assert best.reason
    assert best.risk  # safety class present


def test_selection_never_exceeds_ceiling():
    mastery = _mastery()
    # bug-bounty ceiling is low-impact-active; high-impact tools are excluded.
    decisions = mastery.select("sql-injection-validation", mission_type="bug-bounty")
    for decision in decisions:
        assert decision.risk in ("low-impact-active", "passive")


def test_selection_multiple_results_ordered():
    mastery = _mastery()
    decisions = mastery.select("subdomain-enumeration", mission_type="bug-bounty")
    assert decisions
    scores = [d.score for d in decisions]
    assert scores == sorted(scores, reverse=True)


# -- history -----------------------------------------------------------

def test_record_and_query_history():
    mastery = _mastery()
    entry = mastery.record_run(
        "nuclei",
        "example.com",
        tool_version="3.2.0",
        mission_id="m-1",
        learned="found candidates",
        status=ToolHistoryStatus.COMPLETED,
    )
    assert entry.tool_id == "nuclei"
    assert mastery.has_executed("example.com", "nuclei")
    assert mastery.history("example.com")
    assert mastery.history("other.com") == ()


# -- coverage ----------------------------------------------------------

def test_coverage_report():
    mastery = _mastery()
    report = mastery.coverage()
    assert report.total_tools == len(mastery.tool_ids())
    assert report.by_support_level
    assert "xss-validation" not in report.capability_gaps


# -- datasets ----------------------------------------------------------

def test_datasets_provenance():
    mastery = _mastery()
    seclists = mastery.get_dataset("seclists")
    assert seclists is not None
    assert seclists.license == "MIT"
    assert "ffuf" in seclists.compatibility
    assert len(mastery.datasets()) >= 10


# -- version awareness -------------------------------------------------

def test_version_check():
    mastery = _mastery()
    ok = mastery.check_version("subfinder", "2.14.0")
    assert ok.compatible
    bad = mastery.check_version("subfinder", "1.0.0")
    assert not bad.compatible
    assert mastery.version_ok("subfinder", "2.14.0")
    assert not mastery.version_ok("subfinder", "0.9.0")


# -- port contract -----------------------------------------------------

def test_implements_port():
    mastery = _mastery()
    assert isinstance(mastery, ToolMasteryPort)


# -- arsenal manifest --------------------------------------------------

def test_arsenal_manifest():
    mastery = _mastery()
    manifest = mastery.arsenal().to_manifest()
    assert manifest["manifest_version"] == "1.0.0"
    assert len(manifest["tools"]) >= 80
    assert manifest["tools"]["nuclei"]["support_level"] == "fully-supported"
    assert len(manifest["playbooks"]) == 17
    assert len(manifest["relationships"]) >= 50
    assert len(manifest["datasets"]) >= 10
