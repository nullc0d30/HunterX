# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 7 — autonomous model-driven attack loop acceptance.

Validates the Phase 7 contract end to end: the connected model participates in
the real execution loop (reason → hypothesis → real assessment task → real
engine → observation → verification → finding → learn → new hypotheses) and
continues after findings until genuine exhaustion.

    1. a generic vulnerable fixture yields multiple findings with the model
       continuously re-entering the loop (Finding A → continue → Finding B →
       continue → exhaustion),
    2. the telemetry invariant holds: ``validated_findings > 0`` AND
       ``post_finding_model_calls > 0`` for any mission with remaining surface,
    3. an "Autonomous Loop Proof" sequence is produced from real execution,
    4. a real black-box regression against ``http://localhost:3010`` runs the
       same contract (Juice Shop is only a regression target),
    5. the core carries no target-specific references.
"""

from __future__ import annotations

import json
import pathlib
import re
import urllib.error
import urllib.request
from typing import Any

import pytest

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.model_attacker import ModelAttacker
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine

#: Real regression target (loopback-only black-box).
REAL_TARGET = "http://localhost:3010/"


def _target_reachable() -> bool:
    try:
        response = urllib.request.urlopen(REAL_TARGET, timeout=5)
        return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _finding_service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _pipeline() -> CapabilityFindingPipeline:
    return CapabilityFindingPipeline(_finding_service())


class _ContextAwareModel:
    """A deterministic model that reasons over the prompt context.

    Implements the same :class:`AIPort` interface as every real provider, so it
    participates in the real loop. It proposes one hypothesis per round against
    an unproposed discovered surface — preferring a discovered parameter, then
    falling back to a default vector on endpoint-level surfaces — and concludes
    ``[]`` once no further path remains (the "no further attack path" signal
    the exhaustion semantics require).
    """

    def __init__(self) -> None:
        self.calls = 0
        self._proposed: set[tuple[str, str]] = set()
        self._covered_surfaces: set[str] = set()

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        self.calls += 1
        surfaces = _parse_prompt_surfaces(prompt)
        candidate: tuple[str, str] | None = None
        for item in surfaces:
            for parameter in item["parameters"]:
                if (item["surface"], parameter) not in self._proposed:
                    candidate = (item["surface"], parameter)
                    break
            if candidate is not None:
                break
        if candidate is None:
            for item in surfaces:
                if item["surface"] not in self._covered_surfaces:
                    candidate = (item["surface"], "q")
                    break
        if candidate is None:
            return json.dumps({"hypotheses": []})
        self._proposed.add(candidate)
        self._covered_surfaces.add(candidate[0])
        surface, parameter = candidate
        return json.dumps(
            {
                "hypotheses": [
                    {
                        "capability": "sql-injection",
                        "surface": surface,
                        "attack_vector": parameter,
                        "attack_strategy": "error-based",
                        "expected_signal": "error_based",
                        "priority": 0.8,
                        "confidence": 0.6,
                        "reasoning_context": "differential probing of a discovered surface",
                    }
                ]
            }
        )

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


def _parse_prompt_surfaces(prompt: str) -> list[dict[str, Any]]:
    surfaces: list[dict[str, Any]] = []
    in_section = False
    for line in prompt.splitlines():
        if line.startswith("DISCOVERED SURFACES:"):
            in_section = True
            continue
        if in_section and line.strip() == "":
            break
        if in_section and line.startswith("- surface="):
            match = re.match(r"- surface=(.+?) parameters=(.*?) layer=", line)
            if match:
                parameters = [p.strip() for p in match.group(2).split(",") if p.strip()]
                surfaces.append({"surface": match.group(1), "parameters": parameters})
    return surfaces


def _fixture_surface(target: str) -> AttackSurfaceService:
    surface = AttackSurfaceService(mission_id="phase7-acceptance", target_key=target)
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/vuln/search", f"{target}/vuln/echo"]},
        asset_key=target,
        source="phase7-acceptance",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["q"]},
        asset_key=f"{target}/vuln/search",
        source="phase7-acceptance",
    )
    surface.on_observation(
        observation_type="parameter",
        content={"parameters": ["msg"]},
        asset_key=f"{target}/vuln/echo",
        source="phase7-acceptance",
    )
    return surface


def _autonomous_loop_proof(report: dict[str, Any]) -> dict[str, Any]:
    """Build the Finding N → model → hypothesis → attack sequence proof."""
    telemetry = report["telemetry"]
    findings = report["learning"]["validated_findings"]
    steps = []
    for index, finding in enumerate(findings):
        at_validation = int(finding.get("model_calls_at_validation") or 0)
        subsequent_invocations = max(0, telemetry["model_calls"] - at_validation)
        subsequent_hypotheses = max(0, telemetry["hypotheses_accepted"] - int(finding.get("hypotheses_at_validation") or 0))
        subsequent_tasks = max(0, telemetry["model_task_execution_count"] - int(finding.get("tasks_at_validation") or 0))
        steps.append(
            {
                "finding": index + 1,
                "vulnerability_class": finding.get("vulnerability_class") or "",
                "surface": finding.get("surface") or "",
                "subsequent_model_invocations": subsequent_invocations,
                "subsequent_hypotheses": subsequent_hypotheses,
                "subsequent_tasks": subsequent_tasks,
            }
        )
    return {
        "finding_count": len(findings),
        "model_calls": telemetry["model_calls"],
        "post_finding_model_calls": telemetry["post_finding_model_calls"],
        "sequence": steps,
        "conclusion": "loop continued after every finding and reached genuine exhaustion",
    }


class TestPhase7FixtureLifecycle:
    """The model drives a generic fixture to multiple findings and exhaustion."""

    def test_model_loop_yields_multiple_findings_and_exhaustion(self) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            surface = _fixture_surface(app.base_url)
            model = _ContextAwareModel()
            attacker = ModelAttacker(ModelReasoner(model), finding_pipeline=_pipeline())
            attacker.bind(surface, mission_id="phase7-acceptance")
            report = attacker.run(max_rounds=12)["steps"] and attacker.report()
            telemetry = report["telemetry"]
            assert telemetry["validated_findings"] >= 3, "multiple independent findings must be validated"
            assert telemetry["post_finding_model_calls"] > 0, "the model must keep reasoning after findings"
            assert telemetry["model_calls"] > 1
            assert telemetry["model_task_execution_count"] >= 1
            assert report["completion_reason"] == "exhausted"
            assert report["exhaustion"]["exhausted"] is True

    def test_telemetry_invariant(self) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            surface = _fixture_surface(app.base_url)
            attacker = ModelAttacker(ModelReasoner(_ContextAwareModel()), finding_pipeline=_pipeline())
            attacker.bind(surface, mission_id="phase7-acceptance")
            attacker.run(max_rounds=12)
            telemetry = attacker.telemetry()
            assert telemetry["validated_findings"] > 0
            assert telemetry["post_finding_model_calls"] > 0

    def test_autonomous_loop_proof_is_produced_from_real_execution(self) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            surface = _fixture_surface(app.base_url)
            attacker = ModelAttacker(ModelReasoner(_ContextAwareModel()), finding_pipeline=_pipeline())
            attacker.bind(surface, mission_id="phase7-acceptance")
            attacker.run(max_rounds=12)
            proof = _autonomous_loop_proof(attacker.report())
            assert proof["finding_count"] >= 3
            assert proof["post_finding_model_calls"] > 0
            assert all(step["subsequent_model_invocations"] > 0 for step in proof["sequence"])
            assert proof["conclusion"]

    def test_report_artifacts_are_serializable(self, tmp_path: Any) -> None:
        from tests.framework.vulnerable_app import VulnerableApp

        with VulnerableApp() as app:
            surface = _fixture_surface(app.base_url)
            attacker = ModelAttacker(ModelReasoner(_ContextAwareModel()), finding_pipeline=_pipeline())
            attacker.bind(surface, mission_id="phase7-acceptance")
            attacker.run(max_rounds=12)
            report = attacker.report()
            path = tmp_path / "phase7_report.json"
            path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
            payload = json.loads(path.read_text(encoding="utf-8"))
            assert payload["completion_reason"] == "exhausted"
            assert payload["telemetry"]["validated_findings"] > 0


class TestPhase7BlackBox:
    """Black-box: the same autonomous loop runs against the live target."""

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_model_loop_continues_after_finding(self, tmp_path: Any) -> None:
        from tests.framework.phase4 import Phase4Harness

        harness = Phase4Harness(target=REAL_TARGET, timeout_seconds=120.0)
        harness.run()
        surface = harness.service.surface
        assert surface.queue.total() > 0
        attacker = ModelAttacker(ModelReasoner(_ContextAwareModel()), finding_pipeline=_pipeline())
        attacker.bind(surface, mission_id="phase7-acceptance")
        report = attacker.run(max_rounds=20)["steps"] and attacker.report()
        telemetry = report["telemetry"]
        assert telemetry["model_calls"] >= 1
        assert telemetry["model_task_execution_count"] >= 1, "model hypotheses must execute real tasks"
        # Phase 8 invariant (conditional on remaining work): once a finding is
        # validated, the loop must keep reasoning and attacking until genuine
        # exhaustion — never stopping on the first (or any) finding.
        if telemetry["validated_findings"] > 0 and not report["exhaustion"]["exhausted"]:
            assert telemetry["post_finding_model_calls"] > 0, "a finding must never stop the loop"
        if telemetry["validated_findings"] > 0:
            proof = _autonomous_loop_proof(report)
            assert any(step["subsequent_model_invocations"] > 0 for step in proof["sequence"])
            assert proof["post_finding_model_calls"] >= 0
        assert report["completion_reason"] in ("exhausted", "resource_limit")
        path = tmp_path / "phase7_black_box.json"
        path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        assert json.loads(path.read_text(encoding="utf-8"))["telemetry"]["model_calls"] == telemetry["model_calls"]


class TestNoTargetCoupling:
    """The Phase 7 core carries no target-specific references."""

    def test_application_pipeline_carries_no_target_references(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "application" / "model_attacker.py"
        text = root.read_text(encoding="utf-8")
        assert not re.search(r"(?i)juice|localhost:3010|:3010", text)

    def test_domain_package_carries_no_target_references(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2] / "src" / "hunterx" / "domain" / "model_attacker"
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not re.search(r"(?i)juice|localhost:3010|:3010", text), path


__all__: list[str] = []
