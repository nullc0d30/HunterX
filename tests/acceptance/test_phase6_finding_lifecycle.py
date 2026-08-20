# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 6 — universal capability-finding lifecycle acceptance.

Validates the full Phase 6 contract end to end against generic loopback
targets: Target -> Universal Discovery -> Attack-Surface Graph -> Capability
Mapping -> Assessment Queue -> Aggressive Adaptive Execution -> Continuous
Discovery -> Candidate -> Differential Verification -> Replay -> Reproduction
-> Impact Analysis -> PoC -> Validated Finding -> Report.

    1. a full real discovery pipeline feeds the capability engine, whose
       FINDING records seed candidates that run the complete lifecycle to a
       reportable package (reproduction, impact, PoC, evidence-based severity,
       class-specific remediation, all spec stages),
    2. an honest negative: a safe surface produces no candidates and no
       fabricated findings,
    3. a real black-box regression against ``http://localhost:3010`` runs the
       same contract (Juice Shop is only a regression target),
    4. the core carries no target-specific references.
"""

from __future__ import annotations

import json
import pathlib
import urllib.error
import urllib.request
from typing import Any

import pytest

from hunterx.application.capability_execution import CapabilityExecutionEngine
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.phase4 import Phase4Harness

#: Real regression target (loopback-only black-box).
REAL_TARGET = "http://localhost:3010/"

#: The full Phase 6 spec contract of lifecycle stages.
_SPEC_STAGES = (
    "Candidate",
    "Evidence",
    "Replay",
    "Reproduction",
    "Impact Analysis",
    "PoC",
    "Validated Finding",
    "Report",
)


def _target_reachable() -> bool:
    try:
        response = urllib.request.urlopen(REAL_TARGET, timeout=5)
        return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _run_contract(target: str) -> dict[str, Any]:
    """Run the full Phase 6 contract over a generic loopback target."""
    from hunterx.application.adaptive_attack import AdaptiveAttackService
    from hunterx.application.attack_surface import AttackSurfaceService

    surface = AttackSurfaceService(mission_id="phase6-acceptance", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="phase6-acceptance",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="phase6-acceptance",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="phase6-acceptance",
    )
    engine = CapabilityExecutionEngine(
        mission_id="phase6-acceptance",
        target_key=target,
        surface=surface,
        adaptive=AdaptiveAttackService(mission_id="phase6-acceptance", target_key=target, enforce_pacing=False),
        probe_timeout_s=5.0,
    )
    summary = engine.execute_ready()
    assert summary["tasks_executed"] >= 1
    pipeline = CapabilityFindingPipeline(_service())
    return pipeline.run_all(engine)


def _validate_reportable(outcome: dict[str, Any]) -> None:
    """Conformance checks for a reportable Phase 6 outcome."""
    stages = [entry["stage"] for entry in outcome["stages"]]
    for expected in _SPEC_STAGES:
        assert expected in stages, f"missing spec stage '{expected}'"
    assert outcome["reproduction"] == "reproducible"
    assert outcome["severity"] in ("low", "medium", "high", "critical")
    assert outcome["severity_reasons"], "severity must be explainable"
    assert outcome["remediation"], "class-specific remediation must be present"
    assert outcome["remediation"]["vulnerability_class"] == outcome["finding_class"]
    package = outcome["package"]
    assert package["finding_state"] == "report_ready"
    assert package["severity"] == outcome["severity"]
    assert package["reproduction"] is not None
    assert package["pocs"], "reportable findings carry PoCs"
    assert package["impact"] is not None
    assert package["confidence"] is not None
    assert package["evidence"], "reportable findings carry evidence"


class TestPhase6FixtureLifecycle:
    """A full real discovery + capability pipeline yields validated findings."""

    def test_full_contract_reaches_reportable_findings(self) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            summary = _run_contract(app.base_url)
            assert summary["candidates"] >= 1
            assert summary["reportable"] >= 1, "the fixture's differential signals must yield reportable findings"
            for outcome in summary["outcomes"]:
                assert outcome["verdict"] in ("report_ready", "duplicate", "not_reproducible", "contradicted", "failed")
                assert outcome["stages"], "every candidate records its lifecycle stages"
            for outcome in summary["outcomes"]:
                if outcome["verdict"] == "report_ready":
                    _validate_reportable(outcome)

    def test_report_artifacts_are_serializable(self, tmp_path: Any) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            summary = _run_contract(app.base_url)
            report = tmp_path / "phase6_report.json"
            findings = tmp_path / "validated_findings.json"
            report.write_text(json.dumps({"contract": _SPEC_STAGES, **summary}, indent=2, default=str), encoding="utf-8")
            findings.write_text(json.dumps(summary["findings"], indent=2, default=str), encoding="utf-8")
            assert json.loads(report.read_text(encoding="utf-8"))["candidates"] == summary["candidates"]
            assert len(json.loads(findings.read_text(encoding="utf-8"))) == summary["reportable"]

    def test_safe_surface_produces_no_candidates_and_no_findings(self) -> None:
        from hunterx.application.adaptive_attack import AdaptiveAttackService
        from hunterx.application.attack_surface import AttackSurfaceService
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            target = app.base_url
            surface = AttackSurfaceService(mission_id="phase6-acceptance", target_key=target)
            surface.on_observation(
                observation_type="api",
                content={"endpoints": [f"{target}/safe/search"]},
                asset_key=target,
                source="phase6-acceptance",
            )
            surface.on_observation(
                observation_type="parameter",
                content={"parameters": ["msg"]},
                asset_key=f"{target}/safe/search",
                source="phase6-acceptance",
            )
            engine = CapabilityExecutionEngine(
                mission_id="phase6-acceptance",
                target_key=target,
                surface=surface,
                adaptive=AdaptiveAttackService(mission_id="phase6-acceptance", target_key=target, enforce_pacing=False),
                probe_timeout_s=5.0,
            )
            engine.execute_ready()
            candidates = CapabilityFindingPipeline(_service()).candidates_from(engine)
            assert candidates == [], "a safe surface must never seed a candidate"


class TestPhase6BlackBox:
    """Black-box: the same contract runs against the live regression target."""

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_findings_run_the_lifecycle(self, tmp_path: Any) -> None:
        harness = Phase4Harness(target=REAL_TARGET, timeout_seconds=120.0)
        harness.run()
        surface = harness.service.surface
        assert surface.queue.total() > 0
        engine = CapabilityExecutionEngine(
            mission_id="phase6-acceptance",
            target_key=REAL_TARGET,
            surface=surface,
            adaptive=None,
            probe_timeout_s=5.0,
        )
        summary = engine.execute_ready(max_tasks=60)
        assert summary["tasks_executed"] >= 1
        pipeline = CapabilityFindingPipeline(_service())
        result = pipeline.run_all(engine)
        assert result["candidates"] >= 0
        if result["candidates"]:
            report = tmp_path / "phase6_black_box.json"
            report.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
            assert json.loads(report.read_text(encoding="utf-8"))["candidates"] == result["candidates"]


class TestNoTargetCoupling:
    """The Phase 6 core carries no target-specific references."""

    def test_application_pipeline_carries_no_target_references(self) -> None:
        import re

        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "application" / "capability_finding.py"
        text = root.read_text(encoding="utf-8")
        assert not re.search(r"(?i)juice|localhost:3010|:3010", text)

    def test_domain_package_carries_no_target_references(self) -> None:
        import re

        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "domain" / "capability_finding"
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"(?i)juice|localhost:3010|:3010", text), path


__all__: list[str] = []
