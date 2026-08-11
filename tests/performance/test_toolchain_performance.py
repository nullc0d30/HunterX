# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Performance benchmarks for the full toolchain (Sprint 031).

Executed by the performance quality gate with pytest-benchmark. Covers parser
throughput (subfinder JSONL, dnsx JSONL, nuclei JSONL), normalization
throughput, knowledge-fixture synthesis and selection scoring for large tool
catalogs. No external binary is ever invoked.
"""

from __future__ import annotations

import json

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.tool_intelligence import ToolSelectionCriteria
from hunterx.tools.dns.dnsx import DnsxAdapter
from hunterx.tools.intelligence.compatibility import CompatibilityEngine
from hunterx.tools.intelligence.registry import ToolIntelligenceRegistry
from hunterx.tools.intelligence.selection import ToolSelectionEngine
from hunterx.tools.mastery.api import ToolMasteryAPI
from hunterx.tools.mastery.knowledge_fixtures import ToolKnowledgeFixtureRegistry
from hunterx.tools.recon.runner import CommandResult
from hunterx.tools.recon.subfinder import SubfinderAdapter
from hunterx.tools.vuln.nuclei import NucleiAdapter

_SUBFINDER_LINE = {"host": "api.example.com", "ip": "93.184.216.34", "source": "crt.sh"}
_DNSX_LINE = {"host": "example.com", "type": "A", "ttl": 300, "resp": "93.184.216.34", "resolver": "1.1.1.1"}
_NUCLEI_LINE = {
    "template-id": "exposure-test",
    "info": {"name": "Exposure Test", "severity": "medium", "classification": {"cve-id": "CVE-2021-0001"}},
    "matched-at": "https://example.com/",
    "type": "http",
    "host": "example.com",
    "matcher-status": "true",
}


def _jsonl(lines: list[dict], count: int) -> str:
    return "\n".join(json.dumps(lines[index % len(lines)]) for index in range(count))


def test_subfinder_parse_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Parse 10k subfinder JSONL records (host + ip each)."""
    adapter = SubfinderAdapter()
    context = ExecutionContext(tool_id="subfinder", target="example.com")
    result = CommandResult(returncode=0, stdout=_jsonl([_SUBFINDER_LINE], 10_000))

    def _run() -> int:
        return len(adapter.parse_output(context, result))

    benchmark(_run)


def test_dnsx_parse_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Parse 10k dnsx JSONL records."""
    adapter = DnsxAdapter()
    context = ExecutionContext(tool_id="dnsx", target="example.com")
    result = CommandResult(returncode=0, stdout=_jsonl([_DNSX_LINE], 10_000))

    def _run() -> int:
        return len(adapter.parse_output(context, result))

    benchmark(_run)


def test_nuclei_parse_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Parse 5k nuclei JSONL records into candidates (never findings)."""
    adapter = NucleiAdapter()
    context = ExecutionContext(tool_id="nuclei", target="https://example.com")
    result = CommandResult(returncode=0, stdout=_jsonl([_NUCLEI_LINE], 5_000))

    def _run() -> int:
        return len(adapter.parse_output(context, result))

    benchmark(_run)


def test_knowledge_fixture_synthesis_throughput(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Synthesize the knowledge contract for every arsenal tool."""
    mastery = ToolMasteryAPI()
    registry = ToolKnowledgeFixtureRegistry(mastery.registry, mastery.relationship_graph, mastery.dataset_registry)

    def _run() -> int:
        return len(registry.fixtures())

    benchmark(_run)


def test_selection_throughput_full_catalog(benchmark) -> None:  # type: ignore[no-untyped-def]
    """Score the full arsenal for a capability requirement."""
    registry = ToolIntelligenceRegistry()
    mastery = ToolMasteryAPI()
    for profile in mastery.registry.list():
        registry.register_metadata(profile.metadata)
        registry.register_knowledge(profile.knowledge)
        if profile.compatibility is not None:
            registry.register_compatibility(profile.compatibility)
    engine = ToolSelectionEngine(registry, CompatibilityEngine(registry))
    criteria = ToolSelectionCriteria(
        required_capabilities=("subdomain-discovery",),
        require_installed=False,
        limit=5,
    )

    def _run() -> int:
        return len(engine.select(criteria))

    benchmark(_run)
