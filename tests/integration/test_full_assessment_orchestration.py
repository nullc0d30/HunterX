# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""v7.0.1 regression tests: full_security_assessment orchestration.

Reproduces the defect where ``full_security_assessment`` ran a fixed
reconnaissance chain, entered reporting, and terminated with an internally
inconsistent ``resource_budget_exhausted`` while ``executions_used=8 <<
executions_budget=1000`` and no hypothesis/active-testing ever ran.

Each test proves one of the acceptance criteria from the fix specification:

1. Recon completion must not equal mission completion.
2. An actionable observation produces a hypothesis (or an explicit
   non-actionable classification).
3. A web endpoint + available capability schedules/executes an active probe.
4. ``resource_budget_exhausted`` is emitted only when the budget is actually
   exhausted.
5. An OpenRouter 429 is recorded as an AI failure + fallback, never as a
   budget exhaustion.
6. Browser unavailable ⇒ ``browser_testing = NOT_ASSESSED`` while non-browser
   web assessment continues.
7. A Nuclei ``deprecated-tls`` observation reaches the hypothesis pipeline.
8. The planner selects a registered provider/tool for an applicable hypothesis.
9. Two targets both progress beyond the fixed initial reconnaissance.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from hunterx.application.ai_suggestion import AIActionSuggester
from hunterx.domain.vulnerability_capability.models import ProbeSignal, ProbeVerdict
from hunterx.domain.vulnerability_capability.registry import canonical_class, is_vulnerability_class
from tests.integration.full_assessment_harness import (
    MINIMAL_WEB_OUTPUTS,
    RICH_WEB_OUTPUTS,
    FakeExecutionEngine,
    build_runner,
)

_LOOPBACK = "http://localhost:3010"
_EXTERNAL = "https://www.tosinkuzzy.com"


def _mission(orchestration, target: str = _LOOPBACK, *, objective: str = "full_security_assessment"):
    mission = orchestration.create_mission(objective=objective, target=target)
    mission.policy = dataclasses.replace(mission.policy, coverage_target=0.99)
    orchestration.start(mission.mission_id)
    return mission


def _supported_verdict() -> ProbeVerdict:
    return ProbeVerdict(
        supported=True,
        contradicted=False,
        signal=ProbeSignal.REFLECTED,
        notes="regression-test differential verdict (supported)",
        evidence={"signal": "reflected", "probe": "test"},
    )


class TestReconMustNotEqualCompletion:
    def test_mission_continues_past_recon_into_active_testing(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, planning = build_runner(fake)
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=60, max_idle_cycles=5)

        executed = {call.tool_id for call in fake.calls}
        # The plan is not a fixed recon chain: web discovery capabilities run.
        assert executed & {"katana", "arjun", "kiterunner", "jsluice"} or any(
            action.capability in ("content_discovery", "javascript_analysis", "api_mapping", "parameter_discovery")
            for action in planning.get_plan(mission.mission_id).actions.values()
        ), "web attack-surface discovery must run beyond the initial recon chain"
        # Active-testing probes were scheduled/executed (class-specific tools).
        active_tools = {"sqlmap", "dalfox", "ffuf", "sstimap"}
        assert executed & active_tools, "class-specific active-testing probes must be scheduled"
        # The mission did not merely walk recon → reporting: probes executed.
        assert result["probes_executed"] > 0 or executed & active_tools
        # The outcome is truthful: never a budget exhaustion at 8/1000 executions.
        outcome = mission.outcome
        assert outcome is not None
        assert outcome.stop_condition != "resource_budget_exhausted"

    def test_recon_only_is_never_a_completed_mission(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(MINIMAL_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration)

        # Run enough cycles for recon but not the full assessment.
        runner.run(mission.mission_id, max_cycles=12, max_idle_cycles=2)

        # The planning state must not be COMPLETED merely because recon ran.
        assert mission.mission.state.value != "completed" or mission.outcome is None or not mission.outcome.objectives_complete
        # objectives_complete must not be True while the assessment is unfinished.
        assert mission.outcome is None or mission.outcome.objectives_complete is False


class TestHypothesisGeneration:
    def test_actionable_observation_creates_hypothesis(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=20, max_idle_cycles=3)

        assert mission.hypotheses, "an actionable observation must produce hypotheses"
        class_hypotheses = [
            h
            for h in mission.hypotheses
            if (h.provenance or {}).get("vulnerability_class")
        ]
        assert class_hypotheses, "at least one class-specific hypothesis must exist"

    def test_informational_observation_is_classified_not_dropped(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(MINIMAL_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)

        raw = {
            "observation_type": "vulnerability",
            "content": {
                "findings": [{"template": "deprecated-tls", "severity": "medium", "info": "TLS 1.1"}]
            },
            "confidence": 0.8,
        }
        mission = _mission(orchestration)
        orchestration.ingest_result(
            mission.mission_id,
            tool_id="nuclei",
            asset_key=_LOOPBACK,
            raw=raw,
        )

        # deprecated-tls canonicalizes to a real (mis)configuration class.
        assert canonical_class("deprecated-tls") == "security-misconfiguration"
        assert is_vulnerability_class("deprecated-tls")
        # The observation produced a downstream hypothesis (never a silent drop).
        statements = [h.statement for h in mission.hypotheses]
        assert any("misconfiguration" in statement.lower() for statement in statements) or any(
            "TLS" in statement for statement in statements
        ), "deprecated-tls must reach the hypothesis pipeline"


class TestActiveTesting:
    def test_web_endpoint_schedules_class_specific_probe(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, planning = build_runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=30, max_idle_cycles=4)

        active_capabilities = {
            "sql_injection",
            "xss",
            "ssrf",
            "ssti",
            "lfi",
            "idor",
            "api_security",
            "graphql_security",
        }
        executed = {call.tool_id for call in fake.calls}
        bound = {
            a.capability
            for a in planning.get_plan(mission.mission_id).actions.values()
            if a.hypothesis_id
        }
        assert (executed & {"sqlmap", "dalfox", "ffuf"}) or (bound & active_capabilities), (
            "a discovered endpoint with an available capability must schedule an active probe"
        )


class TestBudgetCorrectness:
    def test_resource_budget_exhausted_requires_real_exhaustion(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=30, max_idle_cycles=4)

        assert mission.budget.executions_used < mission.budget.executions_budget
        assert mission.budget.execution_exhausted is False
        assert mission.budget.exhausted is False
        assert mission.budget.time_exhausted is False  # 0 time budget = unlimited
        outcome = mission.outcome
        assert outcome is not None
        assert outcome.stop_condition != "resource_budget_exhausted"
        assert outcome.exhausted_resource == ""

    def test_time_budget_zero_means_unlimited(self) -> None:
        from hunterx.domain.mission_orchestration.models import MissionBudget

        budget = MissionBudget(executions_used=8, executions_budget=1000, time_budget_seconds=0)
        assert budget.exhausted is False
        assert budget.time_exhausted is False
        assert budget.execution_exhausted is False

    def test_negative_budget_rejected_at_configuration(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(MINIMAL_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        with pytest.raises(ValueError):
            orchestration.create_mission(objective="full_security_assessment", target=_LOOPBACK, time_budget_seconds=-1)
        with pytest.raises(ValueError):
            orchestration.create_mission(objective="full_security_assessment", target=_LOOPBACK, resource_budget=-5)


class _RateLimitedAI:
    """AI client that always raises an HTTP 429-style provider error."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        self.prompts.append(prompt)

        class _RateLimitError(RuntimeError):
            status_code = 429

        raise _RateLimitError("rate limit exceeded")


class TestOpenRouterFailure:
    def test_429_is_recorded_and_mission_continues_deterministically(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(MINIMAL_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        runner._ai_suggester = AIActionSuggester(_RateLimitedAI(), provider="openrouter", model="free-model")  # noqa: SLF001
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=12, max_idle_cycles=3)

        # The AI failure was recorded (invoked but failed, 429).
        ai_entries = [
            dict(e.content or {})
            for e in mission.trace
            if dict(e.content or {}).get("ai_invoked")
        ]
        assert ai_entries, "an AI invocation must be recorded"
        assert all(not entry.get("ai_usable") for entry in ai_entries)
        assert any(entry.get("ai_http_status") == 429 for entry in ai_entries), "HTTP 429 must be recorded"
        assert any(entry.get("ai_error") for entry in ai_entries)
        # The mission continued deterministically despite the AI failure.
        assert result["tool_executions"] > 0
        # The terminal is NOT a budget exhaustion.
        outcome = mission.outcome
        assert outcome is not None
        assert outcome.stop_condition != "resource_budget_exhausted"
        assert outcome.exhausted_resource == ""


class TestBrowserUnavailable:
    def test_browser_not_assessed_but_web_assessment_continues(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)

        def _no_browser() -> dict[str, Any]:
            return {"status": "unavailable", "reason": "playwright missing", "playwright": False}

        monkeypatch.setattr(
            "hunterx.domain.mission_orchestration.browser.detect_browser_capability",
            lambda: _no_browser(),
        )
        mission = _mission(orchestration)

        result = runner.run(mission.mission_id, max_cycles=20, max_idle_cycles=3)

        cell = mission.coverage_cell(_LOOPBACK, "browser_testing")
        assert cell is not None, "browser_testing coverage cell must be recorded"
        assert cell.state.value == "not_assessed", "unavailable browser must stay NOT_ASSESSED"
        assert "browser" in result, "the run result must carry the browser report"
        assert result["browser"]["status"] == "unavailable"
        # Non-browser web assessment continued.
        assert result["tool_executions"] > 0
        assert len(fake.calls) > 0


class TestNucleiObservationPropagation:
    def test_deprecated_tls_reaches_hypothesis_and_finding_pipeline(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(MINIMAL_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration)

        raw = {
            "observation_type": "vulnerability",
            "content": {
                "findings": [{"template": "deprecated-tls", "severity": "medium", "info": "TLS 1.1"}]
            },
            "confidence": 0.8,
        }
        orchestration.ingest_result(
            mission.mission_id,
            tool_id="nuclei",
            asset_key=_LOOPBACK,
            raw=raw,
        )

        # The observation reached the hypothesis pipeline with the canonical
        # class (security-misconfiguration).
        assert any(
            (h.provenance or {}).get("vulnerability_class") == "security-misconfiguration"
            for h in mission.hypotheses
        ), "deprecated-tls must produce a security-misconfiguration hypothesis"
        # It also produced a candidate finding (evidence pipeline).
        assert any(
            finding.get("vulnerability_class") == "security-misconfiguration"
            for finding in mission.context.findings
        ), "deprecated-tls must produce a candidate finding"


class TestToolSelection:
    def test_planner_selects_registered_tool_for_hypothesis(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, planning = build_runner(fake)
        mission = _mission(orchestration)

        runner.run(mission.mission_id, max_cycles=30, max_idle_cycles=4)

        # A class-specific probe action was bound to a hypothesis and the
        # capability-aware selector bound a real registered tool.
        bound = [
            (a.capability, a.hypothesis_id, a.selected_tool)
            for a in planning.get_plan(mission.mission_id).actions.values()
            if a.hypothesis_id
        ]
        assert bound, "hypothesis-bound probe actions must be planned"
        assert all(hypothesis_id for _, hypothesis_id, _ in bound), "probe action must be bound to a hypothesis"
        # At least one bound probe ran a real tool from the candidates.
        candidates_by_capability = {
            "sql_injection": ("sqlmap", "ghauri"),
            "xss": ("dalfox", "xssstrike"),
            "ssrf": ("ffuf", "nuclei"),
            "lfi": ("ffuf", "nuclei"),
            "idor": ("ffuf", "nuclei"),
        }
        executed = {call.tool_id for call in fake.calls}
        selected_tools = {tool for _, _, tool in bound}
        assert any(
            tool in candidates_by_capability.get(capability, ())
            for capability, _, tool in bound
        ) or selected_tools & executed or executed & {"sqlmap", "dalfox", "ffuf"}


class TestTwoTargetRegression:
    def test_loopback_target_progresses_beyond_recon(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration, target=_LOOPBACK)

        runner.run(mission.mission_id, max_cycles=40, max_idle_cycles=4)

        executed = {call.tool_id for call in fake.calls}
        assert mission.hypotheses, "loopback target must generate hypotheses"
        assert executed & {"sqlmap", "dalfox", "ffuf"} or any(
            o.observation_type == "probe" for o in mission.observations
        ), "loopback target must perform active testing"
        assert mission.outcome is None or mission.outcome.stop_condition != "resource_budget_exhausted"

    def test_external_target_progresses_beyond_recon(self) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration, target=_EXTERNAL)

        runner.run(mission.mission_id, max_cycles=40, max_idle_cycles=4)

        executed = {call.tool_id for call in fake.calls}
        assert mission.hypotheses, "external target must generate hypotheses"
        web_discovery = {"katana", "arjun", "kiterunner", "jsluice"}
        assert executed & web_discovery or any(
            action.capability in ("content_discovery", "parameter_discovery", "api_mapping", "javascript_analysis")
            for action in runner._planning.get_plan(mission.mission_id).actions.values()  # noqa: SLF001
        ), "external target must extend past the fixed recon chain"
        assert mission.outcome is None or mission.outcome.stop_condition != "resource_budget_exhausted"

    def test_hypothesis_verify_loop_validates_and_promotes_finding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeExecutionEngine(outputs=dict(RICH_WEB_OUTPUTS))
        runner, orchestration, _ = build_runner(fake)
        mission = _mission(orchestration, target=_LOOPBACK)

        # A supported differential verdict validates a hypothesis, which
        # promotes the linked candidate finding (hypothesis → probe → verify →
        # finding).
        monkeypatch.setattr(runner, "_differential_verdict", lambda mission_id, hypothesis: _supported_verdict())

        runner.run(mission.mission_id, max_cycles=40, max_idle_cycles=4)

        validated = [
            h for h in mission.hypotheses if h.state.value == "validated"
        ]
        verified = [
            f for f in mission.context.findings if f.get("stage") in ("verified", "proven", "report_ready")
        ]
        assert validated, "a supported differential verdict must validate a hypothesis"
        assert verified, "a validated hypothesis must promote a verified finding"
