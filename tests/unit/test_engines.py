# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Functional tests for the engine layer."""

from __future__ import annotations

import json

import pytest

from hunterx.engines.correlation import TargetCorrelator
from hunterx.engines.mission import MissionEngine
from hunterx.engines.planner import DeterministicPlanner
from hunterx.engines.reasoning import ReasoningEngine
from hunterx.engines.report import ReportEngine
from hunterx.engines.workflow import WorkflowDefinition, WorkflowEngine, WorkflowStep
from hunterx.reporting.renderers import JsonRenderer, MarkdownRenderer
from hunterx.shared.result import Failure, Success
from hunterx.tools.executor import ToolExecutor
from hunterx.tools.registry import ToolRegistry
from tests.framework.fakes import FailingTool, FakeAIClient, StaticScanner


def _build_workflow_engine() -> WorkflowEngine:
    registry = ToolRegistry()
    executor = ToolExecutor(registry)
    executor.register_tool("static.scanner", StaticScanner())
    executor.register_tool("failing.tool", FailingTool())
    workflow = WorkflowEngine(executor=executor)
    workflow.register(
        WorkflowDefinition(
            name="smoke",
            steps=(
                WorkflowStep(id="a", action="static.scanner", parameters={"severity": "high"}),
                WorkflowStep(id="b", action="static.scanner", parameters={}, depends_on=("a",)),
            ),
        )
    )
    return workflow


class TestPlanner:
    def test_planner_expands_mission(self) -> None:
        from hunterx.domain.entities import Mission, MissionKind

        mission = Mission(name="recon", kind=MissionKind.RECON, workflow="smoke", targets=["a.com", "b.com"])
        plan = DeterministicPlanner().plan(mission)
        assert len(plan.steps) == 2 * 3  # 2 targets x 3 recon actions
        assert all(step.target in ("a.com", "b.com") for step in plan.steps)


class TestWorkflowEngine:
    def test_run_executes_all_steps(self) -> None:
        workflow = _build_workflow_engine()
        result = workflow.run("smoke", targets=["example.com"])
        assert isinstance(result, Success)
        assert len(result.value) == 2

    def test_run_unknown_workflow_fails(self) -> None:
        workflow = _build_workflow_engine()
        result = workflow.run("missing", targets=["x"])
        assert isinstance(result, Failure)

    def test_invalid_workflow_rejected(self) -> None:
        registry = ToolRegistry()
        executor = ToolExecutor(registry)
        workflow = WorkflowEngine(executor=executor)
        with pytest.raises(Exception):
            workflow.register(
                WorkflowDefinition(name="bad", steps=(WorkflowStep(id="x", action="a", depends_on=("ghost",)),))
            )


class TestToolExecutor:
    def test_execute_returns_findings(self) -> None:
        registry = ToolRegistry()
        executor = ToolExecutor(registry)
        executor.register_tool("static.scanner", StaticScanner())
        output = executor.execute("static.scanner", "example.com", {})
        assert output.ok
        assert len(output.findings) == 1
        assert output.findings[0].title.startswith("Test issue")

    def test_execute_missing_tool_reports_error(self) -> None:
        registry = ToolRegistry()
        executor = ToolExecutor(registry)
        output = executor.execute("nope.tool", "example.com", {})
        assert not output.ok
        assert "not found" in output.error

    def test_execute_failing_tool_captures_error(self) -> None:
        registry = ToolRegistry()
        executor = ToolExecutor(registry)
        executor.register_tool("failing.tool", FailingTool())
        output = executor.execute("failing.tool", "example.com", {})
        assert not output.ok
        assert "boom" in output.error


class TestMissionEngine:
    def _engine(self, event_bus, mission_repository, finding_repository):
        workflow = _build_workflow_engine()
        return MissionEngine(
            missions=mission_repository,
            findings=finding_repository,
            planner=DeterministicPlanner(),
            workflows=workflow,
            correlator=TargetCorrelator(),
            event_bus=event_bus,
        )

    def test_start_publishes_event(self, event_bus, mission_repository) -> None:
        from hunterx.domain.entities import Mission

        mission = Mission(name="m", workflow="smoke", targets=["x"])
        mission_repository.save(mission)
        received: list[str] = []
        event_bus.subscribe("mission.started", lambda e: received.append(e.payload["mission_id"]))
        engine = self._engine(event_bus, mission_repository, None)
        result = engine.start(mission.mission_id)
        assert isinstance(result, Success)
        assert received == [mission.mission_id]

    def test_cannot_start_twice(self, mission_repository) -> None:
        from hunterx.domain.entities import Mission

        mission = Mission(name="m", workflow="smoke", targets=["x"])
        mission_repository.save(mission)
        engine = self._engine(None, mission_repository, None)
        engine.start(mission.mission_id)
        second = engine.start(mission.mission_id)
        assert isinstance(second, Failure)


class TestReasoningEngine:
    def test_summarize_with_fake_ai(self) -> None:
        from hunterx.domain.entities import Finding
        from hunterx.domain.value_objects import Severity

        ai = FakeAIClient(response="Exec summary.")
        engine = ReasoningEngine(ai=ai)
        findings = [Finding(title="XSS", severity=Severity.HIGH, target="a", tool="t")]
        result = engine.summarize_findings(findings)
        assert isinstance(result, Success)
        assert result.value == "Exec summary."

    def test_summarize_empty_is_success(self) -> None:
        engine = ReasoningEngine(ai=FakeAIClient())
        result = engine.summarize_findings([])
        assert isinstance(result, Success)
        assert "No findings" in result.value


class TestReportEngine:
    def test_render_json(self, mission_repository, finding_repository, report_repository) -> None:
        from hunterx.domain.entities import Finding, Mission, Report, ReportKind
        from hunterx.domain.value_objects import Severity

        mission = Mission(name="m", workflow="smoke", targets=["example.com"])
        mission_repository.save(mission)
        finding = Finding(title="XSS", severity=Severity.HIGH, target="example.com", tool="scanner")
        finding.compute_content_hash()
        finding_repository.save(finding)
        report = Report(mission_id=mission.mission_id, kind=ReportKind.TECHNICAL, title="R", finding_ids=[finding.finding_id])
        report_repository.save(report)

        engine = ReportEngine(
            reports=report_repository,
            missions=mission_repository,
            findings=finding_repository,
            renderers=[JsonRenderer(), MarkdownRenderer()],
        )
        result = engine.render(report, fmt="json")
        assert isinstance(result, Success)
        payload = json.loads(result.value)
        assert payload["title"] == "R"
        assert payload["findings"][0]["title"] == "XSS"

    def test_render_unknown_format_fails(self, mission_repository, finding_repository, report_repository) -> None:
        from hunterx.domain.entities import Report, ReportKind

        report = Report(mission_id="nonexistent", kind=ReportKind.TECHNICAL, title="R")
        report_repository.save(report)
        engine = ReportEngine(
            reports=report_repository,
            missions=mission_repository,
            findings=finding_repository,
            renderers=[JsonRenderer()],
        )
        result = engine.render(report, fmt="pdf")
        assert isinstance(result, Failure)
