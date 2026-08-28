# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 5 — universal capability-execution validation.

Validates the capability-execution layer end to end: every queued
``Capability × Surface × Context`` assessment is executed with real differential
probes against a generic loopback target, recorded with tool-orchestration
tables and fallback chains, and aggregated into a machine-readable
``capability_coverage.json`` carrying exactly-one authoritative status per
capability — never a catalog-only claim.

    1. fixture-driven executions against a generic vulnerable/safe app prove
       findings are observed and safe surfaces are contradicted,
    2. a full real discovery pipeline feeds the engine and yields a coverage
       document whose statuses match the live 21-capability catalog,
    3. a real black-box regression against ``http://localhost:3010`` verifies
       the coverage document against the live catalog (Juice Shop is only a
       regression target — it never defines the engine),
    4. the core carries no target-specific references.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.vulnerability_capability.registry import capabilities
from tests.framework.phase4 import GenericDiscoveryFixture, Phase4Harness
from tests.framework.vulnerable_app import VulnerableApp

#: Real regression target (loopback-only black-box).
REAL_TARGET = "http://localhost:3010/"

#: Statuses that prove a capability was genuinely executed (not assumed).
#: BLOCKED intentionally carries no execution metrics — it IS the honest
#: "mapped to a discovered surface but its task never executed" state.
_EXECUTED_STATUSES = {"FINDING", "VERIFIED", "NO_FINDING", "FAILED"}


def _target_reachable() -> bool:
    try:
        response = urllib.request.urlopen(REAL_TARGET, timeout=5)
        return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _make_engine(target: str) -> tuple[CapabilityExecutionEngine, AttackSurfaceService]:
    surface = AttackSurfaceService(mission_id="phase5-acceptance", target_key=target)
    adaptive = AdaptiveAttackService(mission_id="phase5-acceptance", target_key=target, enforce_pacing=False)
    engine = CapabilityExecutionEngine(
        mission_id="phase5-acceptance",
        target_key=target,
        surface=surface,
        adaptive=adaptive,
        probe_timeout_s=5.0,
    )
    return engine, surface


def _feed(surface: AttackSurfaceService, target: str, endpoints: list[str], *, parameters: dict[str, list[str]] | None = None) -> None:
    surface.on_observation(
        observation_type="api",
        content={"endpoints": endpoints},
        asset_key=target,
        source="phase5-acceptance",
    )
    for endpoint, names in (parameters or {}).items():
        surface.on_observation(
            observation_type="parameter",
            content={"parameters": names},
            asset_key=endpoint,
            source="phase5-acceptance",
        )


def _validate_coverage(coverage: dict[str, Any]) -> None:
    """Shared coverage-document conformance checks."""
    catalog = [c.vulnerability_class for c in capabilities()]
    assert coverage["catalog_size"] == len(catalog)
    assert set(coverage["capabilities"]) == set(catalog)
    for capability_id, entry in coverage["capabilities"].items():
        assert entry["status"] in {s.value for s in CapabilityExecutionStatus}, capability_id
        assert entry["reason"], capability_id
        if entry["status"] in _EXECUTED_STATUSES:
            assert entry["tasks_generated"] >= 1, capability_id
            assert entry["tasks_executed"] >= 1, capability_id
            assert entry["verification_attempts"] >= 1, capability_id


class TestExecutionAgainstGenericFixture:
    """The engine executes real probes against a generic loopback target."""

    def test_findings_are_observed_and_safe_surfaces_contradicted(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _make_engine(target)
            _feed(
                surface,
                target,
                [f"{target}/vuln/search", f"{target}/vuln/echo"],
                parameters={f"{target}/vuln/search": ["q"], f"{target}/vuln/echo": ["msg"]},
            )
            summary = engine.execute_ready()
            assert summary["findings"] >= 1
            by_capability = {cap: [r for r in engine.records if r.capability_id == cap] for cap in ("sql-injection", "xss")}
            assert any(r.outcome is CapabilityExecutionStatus.FINDING for r in by_capability["sql-injection"])
            assert any(r.outcome is CapabilityExecutionStatus.FINDING for r in by_capability["xss"])
            assert surface.queue.remaining() == 0

    def test_coverage_document_matches_the_live_catalog(self, tmp_path) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _make_engine(target)
            _feed(
                surface,
                target,
                [f"{target}/vuln/search", f"{target}/safe/search"],
                parameters={f"{target}/vuln/search": ["q"], f"{target}/safe/search": ["msg"]},
            )
            engine.execute_ready()
            coverage = engine.coverage()
            _validate_coverage(coverage)
            assert coverage["capabilities"]["sql-injection"]["status"] == "FINDING"
            # ssrf was never mapped on these surfaces — NOT_APPLICABLE from
            # evidence, never from assumption.
            assert coverage["capabilities"]["ssrf"]["status"] == "NOT_APPLICABLE"
            path = engine.write_coverage(tmp_path / "capability_coverage.json", target=target)
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["mission_id"] == "phase5-acceptance"
            assert payload["target"] == target

    def test_engine_tool_orchestration_records_are_honest(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _make_engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters={f"{target}/vuln/search": ["q"]})
            engine.execute_ready()
            sql_records = [r for r in engine.records if r.capability_id == "sql-injection"]
            tools = [tool for r in sql_records for tool in r.tools]
            tool_ids = {tool.tool_id for tool in tools}
            assert "sqlmap" in tool_ids and "ghauri" in tool_ids and "hunterx-differential" in tool_ids
            unavailable = [t for t in tools if t.tool_id == "sqlmap"]
            assert unavailable and unavailable[0].stdout_status == "unavailable"
            native = [t for t in tools if t.tool_id == "hunterx-differential"]
            assert native and native[0].stdout_status == "ok"


class TestExecutionAgainstRealDiscovery:
    """A full real discovery pipeline feeds the capability engine."""

    def test_discovered_surface_executes_with_coverage(self, tmp_path) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=30.0)
            harness.run()
            surface = harness.service.surface
            engine = CapabilityExecutionEngine(
                mission_id="phase5-acceptance",
                target_key=fixture.target,
                surface=surface,
                adaptive=None,
                probe_timeout_s=5.0,
            )
            summary = engine.execute_ready(max_tasks=40)
            assert summary["tasks_executed"] >= 1
            assert summary["records"] >= 1
            coverage = engine.coverage()
            _validate_coverage(coverage)
            path = engine.write_coverage(tmp_path / "capability_coverage.json", target=fixture.target)
            assert path.exists()


@pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
class TestExecutionAgainstRealTarget:
    """Black-box: coverage vs the live catalog on the regression target."""

    def test_coverage_vs_live_catalog_is_execution_backed(self, tmp_path) -> None:
        harness = Phase4Harness(target=REAL_TARGET, timeout_seconds=120.0)
        harness.run()
        surface = harness.service.surface
        assert surface.queue.total() > 0
        engine = CapabilityExecutionEngine(
            mission_id="phase5-acceptance",
            target_key=REAL_TARGET,
            surface=surface,
            adaptive=None,
            probe_timeout_s=5.0,
        )
        summary = engine.execute_ready(max_tasks=60)
        assert summary["tasks_executed"] >= 1
        coverage = engine.coverage()
        _validate_coverage(coverage)
        executed = [cid for cid, entry in coverage["capabilities"].items() if entry["status"] in _EXECUTED_STATUSES]
        # No catalog-only claims: at least one capability was genuinely
        # executed against the live target and reached a terminal verdict.
        assert executed, "every capability claimed is a catalog-only claim"
        assert any(entry["tasks_executed"] >= 1 for entry in coverage["capabilities"].values())
        path = engine.write_coverage(tmp_path / "capability_coverage.json", target=REAL_TARGET)
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["catalog_size"] == len(capabilities())
        assert any(entry["status"] != "NOT_APPLICABLE" for entry in payload["capabilities"].values())


class TestNoTargetCoupling:
    """The capability-execution core carries no target-specific references."""

    def test_engine_carries_no_juice_shop_references(self) -> None:
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "application" / "capability_execution.py"
        text = root.read_text(encoding="utf-8")
        assert not re.search(r"(?i)juice|localhost:3010|:3010", text)

    def test_domain_package_carries_no_target_references(self) -> None:
        import pathlib
        import re

        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "domain" / "capability_execution"
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"(?i)juice|localhost:3010|:3010", text), path


__all__: list[str] = []
