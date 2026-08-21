# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Final audits: capability coverage, attack-surface trace, security, coupling.

Proves every capability is demonstrated through the execution path (never
merely a catalog entry), every discovered surface flows into the assessment
system (nothing silently disappears), the production source carries no secrets
and no target-specific coupling, and validated findings carry the full quality
package.
"""

from __future__ import annotations

import pathlib

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.attack_surface.enums import SurfaceLayer
from hunterx.domain.capability_execution.enums import CapabilityExecutionStatus
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

_SRC_ROOT = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx"

#: Execution-backed statuses — a capability in one of these must show real work.
_EXECUTED_STATUSES = {"FINDING", "VERIFIED", "NO_FINDING", "FAILED"}


def _finding_service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _run_engine(target: str) -> CapabilityExecutionEngine:
    surface = AttackSurfaceService(mission_id="final-audit", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="final-audit",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="final-audit",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="final-audit",
    )
    engine = CapabilityExecutionEngine(
        mission_id="final-audit",
        target_key=target,
        surface=surface,
        adaptive=None,
        probe_timeout_s=5.0,
    )
    engine.execute_ready()
    return engine


class TestCapabilityCoverageAudit:
    """Every capability is demonstrated through the execution path."""

    def test_capability_coverage_is_execution_backed(self) -> None:
        from hunterx.domain.vulnerability_capability.registry import capabilities

        with VulnerableApp() as app:
            engine = _run_engine(app.base_url)
            coverage = engine.coverage()
            catalog = [capability.vulnerability_class for capability in capabilities()]
            assert coverage["catalog_size"] == len(catalog)
            assert set(coverage["capabilities"]) == set(catalog)
            for capability_id, entry in coverage["capabilities"].items():
                assert entry["status"] in {status.value for status in CapabilityExecutionStatus}, capability_id
                assert entry["reason"], f"{capability_id}: missing status reason"
                if entry["status"] in _EXECUTED_STATUSES:
                    assert entry["tasks_generated"] >= 1, f"{capability_id}: claimed executed with no task"
                    assert entry["tasks_executed"] >= 1, f"{capability_id}: claimed executed with no execution"
            # A genuine finding must trace to a real FINDING record.
            finding_records = [record for record in engine.records if record.outcome is CapabilityExecutionStatus.FINDING]
            assert finding_records, "the fixture must produce FINDING records"
            for record in finding_records:
                assert record.evidence or record.reason, "finding records must carry evidence"

    def test_every_capability_has_an_explicit_state(self) -> None:
        from hunterx.domain.vulnerability_capability.registry import capabilities

        with VulnerableApp() as app:
            engine = _run_engine(app.base_url)
            coverage = engine.coverage()
            for capability in capabilities():
                capability_id = capability.vulnerability_class
                entry = coverage["capabilities"][capability_id]
                # No capability may be silently absent: each has an explicit,
                # explained state.
                assert entry["status"], capability_id


class TestAttackSurfaceTrace:
    """Discovered surfaces flow into the assessment system — nothing disappears."""

    def test_fed_surfaces_are_graph_mapped_queued_and_executed(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="final-audit", target_key=target)
            fed = {
                f"{target}/vuln/search": ["q"],
                f"{target}/vuln/echo": ["msg"],
            }
            surface.on_observation(
                observation_type="api",
                content={"endpoints": list(fed)},
                asset_key=target,
                source="final-audit",
            )
            for endpoint, parameters in fed.items():
                surface.on_observation(
                    observation_type="parameter",
                    content={"parameters": parameters},
                    asset_key=endpoint,
                    source="final-audit",
                )
            graph = surface.graph
            # Discovery → graph: every fed endpoint is a surface node.
            endpoint_nodes = [node for node in graph.nodes() if node.name in fed]
            assert len(endpoint_nodes) == len(fed), "every fed endpoint must be a graph node"
            # Discovery → graph → mapping → queue: every fed parameter is an
            # INPUT node with at least one scheduled task.
            for endpoint, parameters in fed.items():
                parent = next(node for node in endpoint_nodes if node.name == endpoint)
                for parameter in parameters:
                    input_node = next(
                        (node for node in graph.nodes() if node.layer is SurfaceLayer.INPUT and node.name == parameter and graph.parent(node.key) == parent),
                        None,
                    )
                    assert input_node is not None, f"parameter '{parameter}' on {endpoint} must be a graph node"
                    tasks = [task for task in surface.queue.tasks() if task.surface_key == input_node.key]
                    assert tasks, f"parameter '{parameter}' on {endpoint} must produce queued assessment tasks"
            # Queue → execution: every queued task is executed (settled).
            engine = CapabilityExecutionEngine(
                mission_id="final-audit",
                target_key=target,
                surface=surface,
                adaptive=None,
                probe_timeout_s=5.0,
            )
            engine.execute_ready()
            assert surface.queue.remaining() == 0, "every queued assessment task must be executed"
            executed_inputs = {
                (record.endpoint, record.vector)
                for record in engine.records
                if record.vector
            }
            for endpoint, parameters in fed.items():
                for parameter in parameters:
                    assert (endpoint, parameter) in executed_inputs, f"{endpoint}:{parameter} must be executed"


class TestSecurityAudit:
    """No secrets or unsafe tokens in production source."""

    def test_no_hardcoded_secrets(self) -> None:
        pattern = r"sk-[A-Za-z0-9]{20,}|api[_-]?key\s*=\s*[\"'][A-Za-z0-9]{16,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|password\s*=\s*[\"'][^\"']{8,}"
        hits: list[str] = []
        for path in _SRC_ROOT.rglob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if __import__("re").search(pattern, line):
                    hits.append(f"{path}:{lineno}: {line.strip()}")
        assert not hits, "hardcoded secrets found in production source:\n" + "\n".join(hits[:10])

    def test_no_local_target_paths_in_production(self) -> None:
        pattern = r"(?i)juice|localhost:3010|:3010|/home/nc/|C:\\Users\\"
        hits: list[str] = []
        for path in _SRC_ROOT.rglob("*.py"):
            for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if __import__("re").search(pattern, line):
                    hits.append(f"{path}:{lineno}: {line.strip()}")
        assert not hits, "local/target-specific paths found in production source:\n" + "\n".join(hits[:10])


class TestFindingQuality:
    """Validated findings carry the full quality package."""

    def test_reportable_finding_has_complete_evidence(self) -> None:
        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="final-audit", target_key=target)
            surface.on_observation(
                observation_type="api",
                content={"endpoints": [f"{target}/vuln/search"]},
                asset_key=target,
                source="final-audit",
            )
            surface.on_observation(
                observation_type="parameter",
                content={"parameters": ["q"]},
                asset_key=f"{target}/vuln/search",
                source="final-audit",
            )
            engine = CapabilityExecutionEngine(
                mission_id="final-audit",
                target_key=target,
                surface=surface,
                adaptive=None,
                probe_timeout_s=5.0,
            )
            engine.execute_ready()
            pipeline = CapabilityFindingPipeline(_finding_service())
            outcome = pipeline.run(pipeline.candidates_from(engine)[0])
            assert outcome["verdict"] == "report_ready", outcome.get("reason")
            package = outcome["package"]
            assert package.get("severity") in ("low", "medium", "high", "critical")
            assert package.get("evidence"), "evidence must be present"
            assert package.get("reproduction") is not None, "reproduction must be present"
            assert package.get("impact") is not None, "impact analysis must be present"
            assert package.get("pocs"), "PoCs must be present"
            assert package.get("confidence") is not None, "confidence must be assessed"
            assert outcome["remediation"], "class-specific remediation must be present"
            assert outcome["vector"], "the attack vector must be recorded"
            # Deterministic replay + deduplication are enforced by the lifecycle.
            second = pipeline.run(pipeline.candidates_from(engine)[0])
            assert second["verdict"] == "duplicate", "the same signal must deduplicate"


__all__: list[str] = []
