# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack-surface completion — end-to-end targeted reasoning.

Proves HunterX follows evidence: a crawler discovering URLs with query
parameters drives targeted class hypotheses, targeted differential probes, and
validated findings — instead of stopping after generic reconnaissance or
running every class against every endpoint.
"""

from __future__ import annotations

import dataclasses

import pytest

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "endpoint_enumeration": ("httpx",),
    "content_discovery": ("katana",),
    "parameter_discovery": ("arjun",),
    "vulnerability_scanning": ("nuclei",),
    "dependency_check": ("osv-scanner",),
}


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


def _run(app: VulnerableApp, urls: list[str]) -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    outputs = {
        "whatweb": {"name": "python", "technologies": ["Python"]},
        "httpx": {"endpoints": [app.base_url + "/"]},
        "katana": {"urls": urls},
        "nuclei": {"candidates": [], "count": 0},
    }
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=FakeExecutionEngine(outputs=outputs),
    )
    mission = orchestration.create_mission(objective="vulnerability_discovery", target=app.base_url)
    mission.policy = dataclasses.replace(
        mission.policy, coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    runner.run(mission.mission_id, max_cycles=24)
    return runner, orchestration, mission.mission_id


class TestTargetedProbeFromDiscoveredSurface:
    def test_crawler_urls_with_query_params_validate_findings(self, app: VulnerableApp) -> None:
        _, orchestration, mission_id = _run(
            app,
            [
                app.base_url + "/vuln/redirect?to=https://evil.example",
                app.base_url + "/vuln/search?q=1",
            ],
        )
        mission = orchestration.get(mission_id)

        verified = {f.get("vulnerability_class") for f in mission.context.findings if f.get("stage") == "verified"}
        assert "open-redirect" in verified, "a ?to= parameter must yield a validated open-redirect finding"
        assert "sql-injection" in verified, "a ?q= parameter must yield a validated SQL-injection finding"
        validated = [h for h in mission.hypotheses if h.state.value == "validated"]
        assert len(validated) >= 2, "both targeted hypotheses must validate"

    def test_safe_surfaces_refute_not_validate(self, app: VulnerableApp) -> None:
        _, orchestration, mission_id = _run(
            app,
            [
                app.base_url + "/safe/redirect?to=https://evil.example",
                app.base_url + "/safe/search?q=1",
            ],
        )
        mission = orchestration.get(mission_id)
        assert not [f for f in mission.context.findings if f.get("stage") == "verified"]
        for hypothesis in mission.hypotheses:
            if (hypothesis.provenance or {}).get("vulnerability_class"):
                assert hypothesis.state.value == "refuted", (
                    f"{hypothesis.statement} must be refuted by the safe control"
                )

    def test_decision_engine_selects_the_targeted_action(self, app: VulnerableApp) -> None:
        _, orchestration, mission_id = _run(
            app,
            [app.base_url + "/vuln/redirect?to=https://evil.example"],
        )
        mission = orchestration.get(mission_id)
        # The open-redirect hypothesis is derived from evidence and the
        # capability probe was selected for it (a probe must have run).
        assert mission.hypotheses
        open_redirect = next(
            (h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "open-redirect"),
            None,
        )
        assert open_redirect is not None
        assert (open_redirect.provenance or {}).get("parameter") == "to"
        assert open_redirect.state.value == "validated"
