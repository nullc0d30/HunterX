# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the Sprint 033 mission dashboard API.

Builds the full platform and drives the ``/missions`` dashboard route group:
``/overview``, ``/attack-surface``, ``/evidence``, ``/proofs`` and ``/tools``.
Coverage, hypotheses, findings, attack paths and timeline are covered by the
mission orchestration API integration tests.
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


def _create_mission(client: TestClient, *, objective: str = "full_security_assessment") -> str:
    response = client.post("/missions", json={"objective": objective, "target": "https://example.com"})
    assert response.status_code == 200, response.text
    mission_id = response.json()["mission_id"]
    client.post(f"/missions/{mission_id}/start")
    return mission_id


class TestMissionDashboardAPI:
    def test_overview(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        response = client.get(f"/missions/{mission_id}/overview")
        assert response.status_code == 200
        body = response.json()
        assert body["mission_id"] == mission_id
        assert "counts" in body
        assert "coverage_ratio" in body
        assert "budget" in body
        assert "current_phase" in body

    def test_attack_surface(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        client.post(
            f"/missions/{mission_id}/observations",
            json={
                "tool_id": "subfinder",
                "asset_key": "example.com",
                "raw": {"observation_type": "asset", "content": {"subdomains": ["api.example.com"]}, "confidence": 0.9},
            },
        )
        response = client.get(f"/missions/{mission_id}/attack-surface")
        assert response.status_code == 200
        body = response.json()
        assert body["mission_id"] == mission_id
        assert body["assets"]

    def test_evidence(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        client.post(
            f"/missions/{mission_id}/observations",
            json={
                "tool_id": "nuclei",
                "asset_key": "https://example.com/search",
                "raw": {"observation_type": "vulnerability", "content": {"template": "sql-injection"}},
            },
        )
        response = client.get(f"/missions/{mission_id}/evidence")
        assert response.status_code == 200
        body = response.json()
        assert body["mission_id"] == mission_id
        assert len(body["observations"]) == 1

    def test_proofs(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        client.post(
            f"/missions/{mission_id}/coverage",
            json={"asset_key": "https://example.com/search", "capability": "sql_injection", "state": "proved", "tool_id": "sqlmap"},
        )
        response = client.get(f"/missions/{mission_id}/proofs")
        assert response.status_code == 200
        body = response.json()
        assert body["mission_id"] == mission_id
        assert body["proved_cells"]

    def test_tools(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        client.post(
            f"/missions/{mission_id}/observations",
            json={"tool_id": "nuclei", "asset_key": "https://example.com", "raw": {"observation_type": "other"}},
        )
        response = client.get(f"/missions/{mission_id}/tools")
        assert response.status_code == 200
        body = response.json()
        assert body["execution_count"] >= 1

    def test_all_dashboard_endpoints_reachable(self, client: TestClient) -> None:
        mission_id = _create_mission(client)
        for suffix in ("overview", "attack-surface", "evidence", "proofs", "tools"):
            response = client.get(f"/missions/{mission_id}/{suffix}")
            assert response.status_code == 200, suffix
