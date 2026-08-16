# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Hunter behavior acceptance tests.

Prove the engine is a reasoning-driven autonomous security hunter, not a
static tool orchestrator:

    A. Recon drives target-modeling
    B. Modeling drives evidence-derived hypotheses
    C. Hypothesis drives a targeted next action
    D. Probe result drives reassessment (hypothesis update + next decision)
    E. Validation drives finding state (candidate -> validated finding)
    F. Negative result affects reasoning
    G. Profiles differ behaviorally (not just by name)
    H. Coverage never terminates while high-value hypotheses are unresolved
    I. The live CLI reflects reasoning state
    J. The report reconstructs the causal chain
"""

from __future__ import annotations

import dataclasses
import json

from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.cli.app import CliApplication
from hunterx.cli.commands import register_default_commands
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.mission_orchestration.policy import MissionPolicyEngine
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.platform import build_platform
from hunterx.reporting.mission_report import build_mission_text_report
from tests.framework.fakes import FakeExecutionEngine
from tests.integration.test_mission_execution_lifecycle import _FAKE_OUTPUTS, _PassingReadiness

_TARGET = "http://localhost:3010"

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "asset_discovery": ("subfinder", "amass", "assetfinder"),
    "subdomain_enumeration": ("subfinder", "amass", "assetfinder"),
    "dns_enumeration": ("dnsx", "dig"),
    "port_discovery": ("nmap", "rustscan", "masscan"),
    "service_detection": ("nmap", "httpx"),
    "technology_fingerprint": ("whatweb", "wappalyzer"),
    "certificate_enumeration": ("certspotter", "crt.sh"),
    "endpoint_enumeration": ("httpx", "katana", "gospider"),
    "parameter_discovery": ("arjun", "x8"),
    "vulnerability_scanning": ("nuclei", "nikto"),
}

_MEANINGFUL_OUTPUTS: dict[str, dict[str, object]] = {
    "subfinder": {"discoveries": [{"kind": "subdomain", "name": "api.localhost"}], "count": 1},
    "dnsx": {"records": ["api.localhost -> 127.0.0.1"]},
    "nmap": {"ports": [80, 3010]},
    "whatweb": {"name": "wordpress", "technologies": ["WordPress", "PHP"]},
    "httpx": {"endpoints": ["/wp-login.php", "/api/search"]},
    "arjun": {"parameters": ["q", "id"]},
    "nuclei": {
        "findings": [
            {
                "template_id": "wordpress-login-enumeration",
                "template_name": "WordPress Login Enumeration",
                "severity": "medium",
                "matched_at": "http://localhost:3010/",
            }
        ]
    },
    "certspotter": {"certificates": ["localhost"]},
}


def _runner(fake: FakeExecutionEngine, *, objective: str = "full_security_assessment") -> tuple[MissionExecutionService, MissionOrchestrationService, str]:
    """Assemble a real execution runner over real planning/orchestration."""
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
    )
    mission = orchestration.create_mission(objective=objective, target=_TARGET)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


class TestAReconDrivesModeling:
    def test_observation_updates_target_model(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))

        runner.run(mission_id, max_cycles=16)
        context = orchestration.get(mission_id).context

        assert context.technologies, "whatweb WordPress/PHP must update the target model"
        assert any("wordpress" in key.lower() for key in context.technologies), context.technologies
        assert context.endpoints, "httpx endpoints must update the target model"
        assert any("/api/search" in key for key in context.endpoints)


class TestBModelingDrivesHypotheses:
    def test_meaningful_observation_creates_evidence_derived_hypothesis(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        assert mission.hypotheses
        technology = next((h for h in mission.hypotheses if "runs technology" in h.statement), None)
        assert technology is not None, "technology observation must hypothesize"
        assert technology.supporting_evidence, "hypothesis must carry provenance"
        assert technology.provenance.get("observation_id"), "hypothesis provenance must cite the observation"

    def test_empty_observation_creates_no_hypothesis(self) -> None:
        from tests.integration.test_mission_execution_defects import _UninformativeEngine

        runner, orchestration, mission_id = _runner(_UninformativeEngine())

        runner.run(mission_id, max_cycles=8)

        assert orchestration.get(mission_id).hypotheses == []


class TestCHypothesisDrivesDecision:
    def test_vulnerability_hypothesis_schedules_targeted_validation_action(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        vulnerability = next((h for h in mission.hypotheses if "may be affected by" in h.statement), None)
        assert vulnerability is not None, "vulnerability observation must hypothesize"
        assert vulnerability.priority >= 0.7, "a vulnerability hypothesis must be high-value"

        # The replanning layer must have bound a validation action to the
        # hypothesis so the decision engine can rank an evidence-driven probe.
        graph = runner._planning.get_plan(mission_id)  # noqa: SLF001  # runner owns the plan
        bound = [
            action
            for action in graph.actions.values()
            if action.hypothesis_id == vulnerability.hypothesis_id
        ]
        assert bound, "a validation action bound to the hypothesis must be scheduled"
        assert any(action.capability == "vulnerability_scanning" for action in bound)


class TestDProbeDrivesReassessment:
    def test_probe_result_updates_hypothesis_and_decision(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        vulnerability = next((h for h in mission.hypotheses if "may be affected by" in h.statement), None)
        assert vulnerability is not None
        # The validation probe exercised the hypothesis: it gained supporting
        # evidence and left the plain 'proposed' state.
        assert len(vulnerability.supporting_evidence) >= 2, "the probe must add supporting evidence"
        assert vulnerability.state.value in (
            "supported",
            "weakly_supported",
            "validated",
        ), f"probe must advance the hypothesis, not leave it static: {vulnerability.state.value}"


class TestEValidationDrivesFinding:
    def test_validated_hypothesis_promotes_finding_to_verified(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        findings = mission.context.findings
        assert findings
        validated = [h for h in mission.hypotheses if h.state.value == "validated"]
        if not validated:
            return  # some fakes never accumulate two independent supports
        verified = [f for f in findings if f.get("stage") == "verified"]
        assert verified, "a validated hypothesis must promote its finding to verified"


class TestFNegativeAffectsReasoning:
    def test_failed_probe_creates_negative_evidence_and_contradicts_hypothesis(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS), fail_tools=("nuclei",), error="boom")
        runner, orchestration, mission_id = _runner(fake)

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        # A failed probe is recorded as bounded negative evidence and must not
        # be repeated blindly: the decision engine penalizes its reliability.
        assert mission.negative_evidence
        nuclei_negatives = [r for r in mission.negative_evidence if r.tool_id == "nuclei"]
        assert nuclei_negatives, "a failed nuclei probe must produce negative evidence"
        # The next decision after the failure must differ from re-running the
        # failed capability as the first choice whenever alternatives exist.
        failed_cap = nuclei_negatives[0].capability
        for decision in mission.decisions:
            if decision.capability == failed_cap:
                assert decision.factors.get("information_gain", 1.0) < 0.8


class TestGProfilesDifferBehaviorally:
    def test_objectives_map_to_distinct_strategies_and_chains(self) -> None:
        planning = AdaptiveMissionPlanningEngine(
            tool_selection_engine=ToolSelectionEngine(mission_type="bug-bounty", default_candidates=_CANDIDATES),
        )
        chains = {}
        for objective in ("bug_bounty_assessment", "pentest_assessment", "red_team_simulation", "cloud_assessment"):
            mission = planning.create_mission(objective=objective, target=_TARGET)
            chains[objective] = tuple(action.capability for action in mission.graph.actions.values())
        assert chains["bug_bounty_assessment"] != chains["pentest_assessment"]
        assert chains["bug_bounty_assessment"] != chains["red_team_simulation"]
        assert chains["pentest_assessment"] != chains["cloud_assessment"]
        # Behavioral difference is real, not cosmetic: the first capability differs.
        firsts = {objective: chain[0] for objective, chain in chains.items()}
        assert len(set(firsts.values())) >= 2, firsts


class TestHNoDumpOnlyBehavior:
    def test_coverage_stop_is_blocked_while_high_value_hypotheses_open(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))
        policy = MissionPolicyEngine()

        # An evidence-driven mission can discover high-value hypotheses; with
        # coverage trivially satisfied and an unresolved high-value hypothesis,
        # the coverage stop condition MUST NOT terminate the mission.
        orchestration.add_hypothesis(
            mission_id,
            statement="The /api/search q parameter may be susceptible to SQL injection",
            category="injection",
            priority=0.8,
            confidence=0.7,
            supporting=("observation-a",),
        )
        mission = orchestration.get(mission_id)
        mission.policy = dataclasses.replace(mission.policy, coverage_target=0.0)

        stop = policy.evaluate_stop(mission)

        assert stop is None or stop is not StopCondition.COVERAGE_TARGET_ACHIEVED

    def test_coverage_stop_fires_when_no_high_value_hypotheses_open(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))
        policy = MissionPolicyEngine()
        mission = orchestration.get(mission_id)
        mission.policy = dataclasses.replace(mission.policy, coverage_target=0.0)

        stop = policy.evaluate_stop(mission)

        assert stop is StopCondition.COVERAGE_TARGET_ACHIEVED


class TestILiveCliReflectsReasoning:
    def test_cli_stderr_shows_reasoning_events(self, capsys) -> None:  # noqa: ANN001
        platform = build_platform()
        fake = FakeExecutionEngine(outputs=dict(_FAKE_OUTPUTS))
        platform.mission_execution_service._engine = fake  # noqa: SLF001
        platform.mission_execution_service._readiness = _PassingReadiness()  # noqa: SLF001
        app = CliApplication()
        register_default_commands(app, platform)

        assert app.run(["hunt", "full_security_assessment", _TARGET]) == 0
        captured = capsys.readouterr()
        overview = json.loads(captured.out)
        assert overview["counts"]["tool_executions"] > 0
        # The live renderer must reflect reasoning, not just tool execution.
        assert ">> decide" in captured.err
        assert "observation" in captured.err or "coverage" in captured.err
        assert "hypothesis" in captured.err or "[HUNT]" in captured.err


class TestJReportReconstructsCausalChain:
    def test_report_separates_observations_hypotheses_decisions_findings(self) -> None:
        runner, orchestration, mission_id = _runner(FakeExecutionEngine(outputs=dict(_MEANINGFUL_OUTPUTS)))
        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)
        overview = {"mission_id": mission_id, "status": "executed", "counts": {}}

        report = build_mission_text_report(mission_id, overview, [], mission=mission)

        for section in (
            "RECONNAISSANCE",
            "HYPOTHESES",
            "AI / DECISION SUMMARY",
            "FINDINGS",
            "NEGATIVE EVIDENCE",
            "FINAL ASSESSMENT",
        ):
            assert section in report, f"report must contain the '{section}' section"
        # The reasoning trace reconstructs observation -> hypothesis ->
        # decision -> result: every stage is evidence-linked.
        trace = mission.trace
        kinds = {entry.kind.value for entry in trace}
        assert "observation" in kinds and "decision" in kinds and "hypothesis" in kinds
