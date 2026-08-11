# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""REST API authentication and authorization (Sprint 034.4 §15).

The API is unauthenticated by default (trusted loopback, opt-in control
plane). When ``api.auth_enabled`` is set, a valid ``X-API-Key`` is required on
every request and the read-only key cannot issue write operations.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient

from hunterx.api.app import create_app
from hunterx.api.auth import ApiAuthConfig, configure_auth
from hunterx.config.settings import ApiSettings, Settings
from hunterx.platform import build_platform

_ADMIN = "admin-secret-123"
_READONLY = "ro-secret-456"


@pytest.fixture()
def client():
    platform = build_platform()
    settings = Settings(
        api=ApiSettings(auth_enabled=True, api_key=_ADMIN, read_only_key=_READONLY)
    )
    return TestClient(create_app(platform=platform, settings=settings))


@pytest.fixture()
def open_client():
    configure_auth(ApiAuthConfig.disabled())
    return TestClient(create_app(platform=build_platform()))


def test_default_configuration_is_disabled() -> None:
    assert ApiAuthConfig.disabled().enabled is False


def test_role_for_recognizes_admin_and_readonly() -> None:
    config = ApiAuthConfig(enabled=True, api_key=_ADMIN, read_only_key=_READONLY)
    assert config.role_for(_ADMIN) == "admin"
    assert config.role_for(_READONLY) == "readonly"
    assert config.role_for("") is None
    assert config.role_for("unknown") is None


def test_unauthenticated_write_is_rejected(client) -> None:
    response = client.post("/missions", json={"target": "https://example.com"})
    assert response.status_code == 401


def test_unauthenticated_read_is_rejected(client) -> None:
    response = client.get("/missions/whatever")
    assert response.status_code == 401


def test_readonly_key_cannot_execute_or_create(client) -> None:
    headers = {"X-API-Key": _READONLY}
    assert client.post("/missions", json={"target": "x"}, headers=headers).status_code == 403
    assert client.post("/tools/execute", json={"tool_id": "nuclei", "target": "example.com"}, headers=headers).status_code == 403


def test_readonly_key_can_read(client) -> None:
    headers = {"X-API-Key": _READONLY}
    response = client.get("/tools", headers=headers)
    assert response.status_code == 200


def test_admin_key_can_create_mission(client) -> None:
    headers = {"X-API-Key": _ADMIN}
    response = client.post("/missions", json={"target": "https://example.com", "objective": "web"}, headers=headers)
    assert response.status_code == 200, response.text
    assert "mission_id" in response.json()


def test_unknown_key_is_rejected(client) -> None:
    response = client.get("/tools", headers={"X-API-Key": "nope"})
    assert response.status_code == 401


def test_health_probe_is_exempt(client) -> None:
    assert client.get("/health").status_code == 200


def test_disabled_auth_keeps_api_open(open_client) -> None:
    assert open_client.get("/health").status_code == 200
    response = open_client.post("/missions", json={"target": "https://example.com"})
    assert response.status_code == 200
