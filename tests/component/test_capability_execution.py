# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability execution engine — component tests.

The engine runs real, bounded, loopback differential probes against generic
vulnerable/safe fixtures: findings are observed not assumed, blocked is
blocked, failed is failed, and the mission's capability coverage carries
exactly-one authoritative status per capability.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.adaptive_attack import AdaptiveAttackService
from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.domain.vulnerability_capability.registry import capabilities
from tests.framework.vulnerable_app import VulnerableApp


class _FakeSession:
    """An established authenticated session with a cookie."""

    established = True
    state = "authenticated"

    def cookie_header(self) -> str:
        return "session=hxprobe-auth"


class _FakeSessionNoAuth:
    established = False
    state = "anonymous"

    def cookie_header(self) -> str:
        return ""


def _engine(target: str, *, session: Any = None) -> tuple[CapabilityExecutionEngine, AttackSurfaceService]:
    surface = AttackSurfaceService(mission_id="component-phase5", target_key=target)
    adaptive = AdaptiveAttackService(mission_id="component-phase5", target_key=target, enforce_pacing=False)
    engine = CapabilityExecutionEngine(
        mission_id="component-phase5",
        target_key=target,
        surface=surface,
        adaptive=adaptive,
        probe_timeout_s=4.0,
    )
    return engine, surface


def _feed(
    surface: AttackSurfaceService,
    target: str,
    endpoints: list[str],
    *,
    parameters: list[str] | dict[str, list[str]] | None = None,
) -> None:
    surface.on_observation(
        observation_type="api",
        content={"endpoints": endpoints},
        asset_key=target,
        source="phase5-test",
    )
    if parameters is None:
        return
    per_endpoint = parameters if isinstance(parameters, dict) else {endpoint: parameters for endpoint in endpoints}
    # Input surfaces parent under their owning endpoint so evidence points
    # at the endpoint the injection capabilities probe.
    for endpoint, names in per_endpoint.items():
        surface.on_observation(
            observation_type="parameter",
            content={"parameters": names},
            asset_key=endpoint,
            source="phase5-test",
        )


class TestFindingExecution:
    def test_vulnerable_surface_yields_finding(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters=["q"])
            summary = engine.execute_ready()
            assert summary["findings"] >= 1
            sql_records = [r for r in engine.records if r.capability_id == "sql-injection"]
            assert sql_records
            assert any(r.outcome is CapabilityExecutionStatus.FINDING for r in sql_records)
            finding = next(r for r in sql_records if r.outcome is CapabilityExecutionStatus.FINDING)
            assert finding.endpoint.endswith("/vuln/search")
            assert finding.verification_attempts == 1
            assert finding.evidence
            assert finding.strategies  # multi-vector strategies recorded
            assert surface.queue.remaining() == 0

    def test_safe_surface_yields_definite_negative(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/safe/search"], parameters=["q"])
            engine.execute_ready()
            sql_records = [r for r in engine.records if r.capability_id == "sql-injection"]
            assert sql_records
            assert all(r.outcome is CapabilityExecutionStatus.VERIFIED for r in sql_records)
            assert surface.queue.remaining() == 0

    def test_xss_and_ssti_findings(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/echo", f"{target}/vuln/greet"], parameters={f"{target}/vuln/echo": ["q"], f"{target}/vuln/greet": ["name"]})
            engine.execute_ready()
            by_capability = {
                cid: [r for r in engine.records if r.capability_id == cid] for cid in ("xss", "ssti")
            }
            assert any(r.outcome is CapabilityExecutionStatus.FINDING for r in by_capability["xss"])
            assert any(r.outcome is CapabilityExecutionStatus.FINDING for r in by_capability["ssti"])

    def test_safe_and_vulnerable_variants_are_distinguished(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search", f"{target}/safe/search"], parameters={f"{target}/vuln/search": ["q"], f"{target}/safe/search": ["msg"]})
            engine.execute_ready()
            endpoints = {r.endpoint: r for r in engine.records if r.capability_id == "sql-injection"}
            assert endpoints[f"{target}/vuln/search"].outcome is CapabilityExecutionStatus.FINDING
            assert endpoints[f"{target}/safe/search"].outcome is CapabilityExecutionStatus.VERIFIED

    def test_parameter_vector_is_recorded(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters=["q"])
            engine.execute_ready()
            sql_records = [r for r in engine.records if r.capability_id == "sql-injection"]
            assert sql_records
            assert any(r.vector == "q" or r.vector != "" for r in sql_records)


class TestHonestSemantics:
    def test_non_loopback_target_is_blocked_not_fabricated(self) -> None:
        target = "http://example.com/api/products"
        engine, surface = _engine(target)
        _feed(surface, target, [f"{target}/search"])
        engine.execute_ready()
        blocked = [r for r in engine.records if r.outcome is CapabilityExecutionStatus.BLOCKED]
        assert blocked
        assert any("loopback" in r.reason for r in blocked)
        assert all(r.outcome is not CapabilityExecutionStatus.FINDING for r in engine.records)

    def test_unregistered_capability_is_failed(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"])
            # Force a bogus capability assignment into the queue.
            from hunterx.domain.attack_surface.models import CapabilityAssignment
            from hunterx.domain.attack_surface.queue import schedule_assignments

            endpoint_node = next(
                node for node in surface.graph.nodes() if node.name == f"{target}/vuln/search"
            )
            bogus = CapabilityAssignment(
                capability_id="does-not-exist",
                surface_key=endpoint_node.key,
                rationale="forced",
                applicable=True,
            )
            schedule_assignments(surface.queue, [bogus], mission_id="component-phase5", strategy="differential")
            engine.execute_ready()
            failed = [r for r in engine.records if r.capability_id == "does-not-exist"]
            assert failed
            assert failed[0].outcome is CapabilityExecutionStatus.FAILED
            assert "not registered" in failed[0].reason

    def test_blocked_is_never_complete(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/safe/search"])
            engine.execute_ready()
            for task in surface.queue.tasks():
                assert task.status.value != "blocked" or task.verification_state.value == "inconclusive"

    def test_structural_surfaces_are_not_applicable_not_probed(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            surface.on_observation(
                observation_type="host",
                content={},
                asset_key="127.0.0.1",
                source="phase5-test",
            )
            engine.execute_ready()
            # Host nodes carry no probeable input — any record is honest NA.
            assert all(r.outcome is CapabilityExecutionStatus.NOT_APPLICABLE for r in engine.records)


class TestToolOrchestrationAndFallback:
    def test_scanner_fallback_chain_is_recorded_honestly(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters=["q"])
            engine.execute_ready()
            sql_records = [r for r in engine.records if r.capability_id == "sql-injection"]
            tools = [tool for r in sql_records for tool in r.tools]
            tool_ids = {tool.tool_id for tool in tools}
            # sqlmap -> ghauri -> native differential; scanners unavailable.
            assert "sqlmap" in tool_ids
            assert "ghauri" in tool_ids
            assert "hunterx-differential" in tool_ids
            unavailable = [t for t in tools if t.tool_id == "sqlmap"]
            assert unavailable
            assert unavailable[0].stdout_status == "unavailable"
            native = [t for t in tools if t.tool_id == "hunterx-differential"]
            assert native
            assert native[0].stdout_status == "ok"
            assert native[0].parsed_result == "error_based"

    def test_fallback_never_silently_marks_complete(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters=["q"])
            engine.execute_ready()
            for record in engine.records:
                if record.tools:
                    assert any(tool.stdout_status in ("ok", "unavailable", "failed") for tool in record.tools)


class TestAuthContextMatrix:
    def test_anonymous_only_without_session(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/safe/search"])
            engine.execute_ready()
            assert all(r.session_state == "anonymous" for r in engine.records)

    def test_auth_context_matrix_executes_both_contexts(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/safe/search"], parameters=["q"])
            engine.execute_ready(session=_FakeSession())
            contexts = {r.session_state for r in engine.records if r.capability_id == "sql-injection"}
            assert contexts == {"anonymous", "authenticated"}

    def test_unestablished_session_stays_anonymous(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/safe/search"])
            engine.execute_ready(session=_FakeSessionNoAuth())
            assert all(r.session_state == "anonymous" for r in engine.records)


class TestCoveragePersistence:
    def test_coverage_covers_the_live_catalog_with_exactly_one_status(self, tmp_path) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search", f"{target}/vuln/echo"], parameters={f"{target}/vuln/search": ["q"], f"{target}/vuln/echo": ["msg"]})
            engine.execute_ready()
            coverage = engine.coverage()
            catalog = engine.catalog()
            assert coverage["catalog_size"] == len(catalog) == len(capabilities())
            assert len(coverage["capabilities"]) == len(catalog)
            statuses = {entry["status"] for entry in coverage["capabilities"].values()}
            assert statuses <= {s.value for s in CapabilityExecutionStatus}
            assert coverage["capabilities"]["sql-injection"]["status"] == "FINDING"
            assert coverage["capabilities"]["xss"]["status"] == "FINDING"
            # Unmapped capabilities are NOT_APPLICABLE from evidence, not assumption.
            assert coverage["capabilities"]["ssrf"]["status"] == "NOT_APPLICABLE"
            for capability_id, entry in coverage["capabilities"].items():
                assert entry["reason"], capability_id

    def test_coverage_json_persisted_with_mission(self, tmp_path) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"])
            engine.execute_ready()
            path = engine.write_coverage(tmp_path / "capability_coverage.json", target=target)
            assert path.exists()
            import json

            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["mission_id"] == "component-phase5"
            assert payload["target"] == target
            assert payload["catalog_size"] > 0

    def test_task_counts_are_honest(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            engine, surface = _engine(target)
            _feed(surface, target, [f"{target}/vuln/search"], parameters=["q"])
            engine.execute_ready()
            entry = engine.coverage()["capabilities"]["sql-injection"]
            assert entry["tasks_generated"] >= 1
            assert entry["tasks_executed"] >= 1
            assert entry["verification_attempts"] >= 1


__all__: list[str] = []
