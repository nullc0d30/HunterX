# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Mission isolation tests (Sprint 034.3 §5).

MISSION-A and MISSION-B target the same asset. Their tool executions,
hypotheses, evidence, findings, decisions, timelines and state must remain
correctly associated with no cross-mission contamination.
"""

from __future__ import annotations

import pytest

from hunterx.application.mission_orchestration import (
    MissionOrchestrationQueryService,
    MissionOrchestrationService,
)
from hunterx.domain.mission_orchestration.decision import CandidateAction
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine


@pytest.fixture()
def service(backend_factory):
    return MissionOrchestrationService(engine=MissionOrchestrationEngine(), stores=backend_factory)


@pytest.fixture()
def query(backend_factory):
    return MissionOrchestrationQueryService(stores=backend_factory)


def _run_mission_a(service: MissionOrchestrationService) -> str:
    mission = service.create_mission(target="https://example.com", objective="web")
    mid = mission.mission_id
    service.start(mid)
    service.ingest_result(mid, tool_id="httpx", asset_key="https://example.com", raw={"status": 200})
    service.add_hypothesis(mid, statement="SQLi on search", category="injection")
    service.decide_next(
        mid,
        candidates=(
            CandidateAction(action_id="a1", capability="recon", tool_ids=("subfinder",), expected_information_gain=0.8),
        ),
    )
    service.register_finding(mid, finding_id="FA1", vulnerability_class="sql_injection", asset_key="https://example.com/search", stage="proven")
    return mid


def _run_mission_b(service: MissionOrchestrationService) -> str:
    mission = service.create_mission(target="https://example.com", objective="cloud")
    mid = mission.mission_id
    service.start(mid)
    service.ingest_result(mid, tool_id="nuclei", asset_key="https://example.com", raw={"template": "CVE-x"})
    service.add_hypothesis(mid, statement="SSRF via redirect", category="ssrf")
    service.register_finding(mid, finding_id="FB1", vulnerability_class="ssrf", asset_key="https://example.com/redirect", stage="proven")
    return mid


def test_observations_are_mission_scoped(service, query) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    obs_a = query.observations(mid_a)
    obs_b = query.observations(mid_b)
    assert len(obs_a) == 1 and len(obs_b) == 1
    assert obs_a[0].tool_id == "httpx"
    assert obs_b[0].tool_id == "nuclei"


def test_hypotheses_are_mission_scoped(service, query) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    hyp_a = query.hypotheses(mid_a)
    hyp_b = query.hypotheses(mid_b)
    assert len(hyp_a) == 1 and len(hyp_b) == 1
    assert hyp_a[0].category == "injection"
    assert hyp_b[0].category == "ssrf"


def test_decisions_are_mission_scoped(service, query) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    dec_a = query.decisions(mid_a)
    dec_b = query.decisions(mid_b)
    assert len(dec_a) == 1
    assert all(d.mission_id == mid_a for d in dec_a)
    assert all(d.mission_id == mid_b for d in dec_b)


def test_findings_are_mission_scoped(service) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    # Findings live in each mission's isolated context; cross-mission queries
    # can never surface the other mission's findings.
    findings_a = {f["finding_id"] for f in service.engine.get(mid_a).context.findings}
    findings_b = {f["finding_id"] for f in service.engine.get(mid_b).context.findings}
    assert findings_a == {"FA1"}
    assert findings_b == {"FB1"}
    assert findings_a.isdisjoint(findings_b)


def test_mission_state_is_isolated(service, query) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    state_a = service.status(mid_a)
    state_b = service.status(mid_b)
    # Each mission's state reflects only its own lifecycle.
    assert state_a["mission_id"] == mid_a
    assert state_b["mission_id"] == mid_b
    assert state_a["mission_id"] != state_b["mission_id"]

    timeline_a = query.timeline(mid_a)
    timeline_b = query.timeline(mid_b)
    assert all(e.mission_id == mid_a for e in timeline_a)
    assert all(e.mission_id == mid_b for e in timeline_b)


def test_pause_resume_does_not_contaminate(service, query) -> None:
    mid_a = _run_mission_a(service)
    mid_b = _run_mission_b(service)

    service.pause(mid_a)
    service.resume(mid_a)

    # Mission B's records are untouched by A's lifecycle transitions.
    obs_b = query.observations(mid_b)
    assert len(obs_b) == 1
    hyp_b = query.hypotheses(mid_b)
    assert len(hyp_b) == 1
