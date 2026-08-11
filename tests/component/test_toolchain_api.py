# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the ``/tools`` API (Sprint 031)."""

from __future__ import annotations

import pytest

from hunterx.api.app import create_app

fastapi = pytest.importorskip("fastapi")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    app = create_app()
    return TestClient(app)


def test_list_tools(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools")
    assert response.status_code == 200
    tools = response.json()
    assert any(tool["tool_id"] == "nuclei" for tool in tools)


def test_show_tool(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools/nmap")
    assert response.status_code == 200
    payload = response.json()
    assert payload["tool_id"] == "nmap"
    assert "knowledge" in payload


def test_show_unknown_tool_is_404(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools/does-not-exist")
    assert response.status_code == 404


def test_tool_capabilities(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools/ffuf/capabilities")
    assert response.status_code == 200
    assert "directory-discovery" in response.json()


def test_capability_catalog(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools/capabilities")
    assert response.status_code == 200
    capabilities = response.json()
    assert any(item["capability_id"] == "port-scanning" for item in capabilities)


def test_tool_health_and_versions(client) -> None:  # type: ignore[no-untyped-def]
    assert client.get("/tools/nmap/health").status_code == 200
    response = client.get("/tools/nmap/versions")
    assert response.status_code == 200
    assert response.json()["tool_id"] == "nmap"


def test_tool_requirements_and_provenance(client) -> None:  # type: ignore[no-untyped-def]
    assert client.get("/tools/nuclei/requirements").status_code == 200
    provenance = client.get("/tools/nuclei/provenance").json()
    assert provenance["tool_id"] == "nuclei"


def test_recommend(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get("/tools/recommend/port-scanning")
    assert response.status_code == 200
    recommendations = response.json()
    assert recommendations
    assert recommendations[0]["kind"] == "best"


def test_plan_chain(client) -> None:  # type: ignore[no-untyped-def]
    response = client.post("/tools/chain", json={"objective": "Recon", "capabilities": ["subdomain-discovery", "http-probing"]})
    assert response.status_code == 200
    chain = response.json()
    assert chain["objective"] == "Recon"
    assert chain["steps"]


def test_execute_in_process_tool(client) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        "/tools/execute",
        json={"tool_id": "javascript", "target": "https://example.com", "target_type": "url"},
    )
    assert response.status_code == 200
    outcome = response.json()
    assert "execution_id" in outcome
    execution_id = outcome["execution_id"]

    assert client.get(f"/tools/executions/{execution_id}/status").status_code == 200
    assert client.get(f"/tools/executions/{execution_id}/output").status_code == 200
    result = client.get(f"/tools/executions/{execution_id}/result").json()
    assert result["execution_id"] == execution_id


def test_parse_and_normalize_offline(client) -> None:  # type: ignore[no-untyped-def]
    parsed = client.post("/tools/parse", json={"tool_id": "subfinder", "raw": '{"host": "api.example.com"}'})
    assert parsed.status_code == 200
    assert parsed.json()["count"] >= 1

    normalized = client.post(
        "/tools/normalize",
        json={"tool_id": "nuclei", "records": [{"title": "x", "severity": "medium", "target": "t", "description": "d"}]},
    )
    assert normalized.status_code == 200
    assert normalized.json()["counts"]["findings"] == 1
