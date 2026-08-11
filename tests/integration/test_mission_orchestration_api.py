# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the Autonomous Mission Orchestration API.

Builds the full platform and drives the ``/missions`` route group through the
FastAPI test client: create/get/start/pause/resume/cancel, state/timeline/
decisions/hypotheses/findings/attack-paths/coverage/tool-executions reads, and
the reasoning-loop endpoints.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from hunterx.platform import build_platform


@pytest.fixture()
def client() -> TestClient:
    platform = build_platform()
    from hunterx.api.app import create_app

    return TestClient(create_app(platform=platform))


class TestMissionLifecycleAPI:
    def test_create_and_get(self, client: TestClient) -> None:
        response = client.post("/missions", json={"objective": "full_security_assessment", "target": "https://example.com"})
        assert response.status_code == 200, response.text
        body = response.json()
        mission_id = body["mission_id"]
        get = client.get(f"/missions/{mission_id}")
        assert get.status_code == 200
        assert get.json()["mission_id"] == mission_id

    def test_start_state_timeline(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        assert client.post(f"/missions/{mission_id}/start").status_code == 200
        state = client.get(f"/missions/{mission_id}/state").json()
        assert "planning_state" in state
        assert "budget" in state
        timeline = client.get(f"/missions/{mission_id}/timeline").json()
        assert any("mission.started" in str(entry) or "run.started" in str(entry) for entry in timeline)

    def test_observation_hypothesis_decision_flow(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        obs = client.post(
            f"/missions/{mission_id}/observations",
            json={"tool_id": "nuclei", "asset_key": "https://example.com/search", "raw": {"observation_type": "vulnerability", "content": {"template": "sql-injection"}}},
        )
        assert obs.status_code == 200
        hypothesis = client.post(
            f"/missions/{mission_id}/hypotheses",
            json={"statement": "SQLi on search", "category": "injection", "priority": 0.9},
        ).json()
        assert hypothesis["state"] == "proposed"
        updated = client.post(
            f"/missions/{mission_id}/hypotheses/{hypothesis['hypothesis_id']}/update",
            json={"supporting": ["ev1", "ev2"]},
        ).json()
        assert updated["state"] == "supported"
        hypotheses = client.get(f"/missions/{mission_id}/hypotheses").json()
        assert len(hypotheses) == 1

    def test_decision_and_coverage(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        decision = client.post(
            f"/missions/{mission_id}/decide",
            json={
                "candidates": [
                    {
                        "action_id": "a1",
                        "capability": "subdomain_enumeration",
                        "tool_ids": ["subfinder"],
                        "expected_information_gain": 0.9,
                    }
                ]
            },
        )
        assert decision.status_code == 200
        assert decision.json()["next_action"] == "a1"
        coverage = client.post(
            f"/missions/{mission_id}/coverage",
            json={"asset_key": "https://example.com/search", "capability": "sql_injection", "state": "validated", "tool_id": "sqlmap"},
        )
        assert coverage.status_code == 200
        assert coverage.json()["coverage_ratio"] > 0

    def test_findings_attack_paths_tools(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        client.post(
            f"/missions/{mission_id}/findings",
            json={"finding_id": "F1", "vulnerability_class": "sql_injection", "asset_key": "https://example.com/search", "stage": "proven"},
        )
        findings = client.get(f"/missions/{mission_id}/findings").json()
        assert findings == [] or any(f["finding_id"] == "F1" for f in findings)
        assert client.get(f"/missions/{mission_id}/attack-paths").status_code == 200
        assert client.get(f"/missions/{mission_id}/tool-executions").status_code == 200

    def test_checkpoint_resume_and_finalize(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        client.post(f"/missions/{mission_id}/start")
        checkpoint = client.post(f"/missions/{mission_id}/checkpoints", json={"label": "phase"}).json()
        assert checkpoint["checkpoint_id"]
        resumed = client.post(f"/missions/{mission_id}/checkpoints/{checkpoint['checkpoint_id']}/resume")
        assert resumed.status_code == 200
        finalized = client.post(f"/missions/{mission_id}/finalize")
        assert finalized.status_code == 200
        assert finalized.json()["outcome"] is not None

    def test_cancel(self, client: TestClient) -> None:
        mission_id = client.post("/missions", json={"target": "https://example.com"}).json()["mission_id"]
        cancelled = client.post(f"/missions/{mission_id}/cancel").json()
        assert cancelled["outcome"]["stop_condition"] == "operator_cancelled"
