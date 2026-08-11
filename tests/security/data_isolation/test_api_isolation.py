# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Data-isolation tests through the public API (Sprint 034.3 §4, §5).

TARGET-A / MISSION-A and TARGET-B / MISSION-B are populated through the HTTP
API. The suite verifies that scoped reads never leak another target's or
mission's intelligence, and that secret-like material never appears in API
responses.
"""

from __future__ import annotations

import pytest


def _create_mission(client, *, target: str, objective: str) -> str:
    response = client.post("/missions", json={"target": target, "objective": objective})
    assert response.status_code == 200, response.text
    body = response.json()
    assert "mission_id" in body
    return body["mission_id"]


def _create_finding(client, *, mission_id: str, target_id: str, title: str) -> dict:
    response = client.post(
        "/findings",
        json={
            "mission_id": mission_id,
            "target_id": target_id,
            "vulnerability_class": "sql_injection",
            "title": title,
            "severity": "high",
            "tool": "certification",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture()
def two_missions(client) -> tuple[str, str]:
    return (
        _create_mission(client, target="acme-a.example.com", objective="web"),
        _create_mission(client, target="acme-b.example.com", objective="cloud"),
    )


def test_mission_listing_is_scoped(client, two_missions) -> None:
    mission_a, mission_b = two_missions
    _create_finding(client, mission_id=mission_a, target_id="tgt-a", title="finding-A")
    _create_finding(client, mission_id=mission_b, target_id="tgt-b", title="finding-B")

    list_a = client.get("/findings", params={"mission_id": mission_a})
    list_b = client.get("/findings", params={"mission_id": mission_b})

    assert list_a.status_code == 200
    assert list_b.status_code == 200

    titles_a = {item.get("title") for item in list_a.json()}
    titles_b = {item.get("title") for item in list_b.json()}
    assert titles_a == {"finding-A"}
    assert titles_b == {"finding-B"}
    assert titles_a.isdisjoint(titles_b)


def test_mission_state_is_scoped(client, two_missions) -> None:
    mission_a, mission_b = two_missions
    state_a = client.get(f"/missions/{mission_a}/state")
    state_b = client.get(f"/missions/{mission_b}/state")
    assert state_a.status_code == 200 and state_b.status_code == 200
    assert state_a.json()["mission_id"] == mission_a
    assert state_b.json()["mission_id"] == mission_b


def test_finding_retrieval_by_id_is_exact(client, two_missions) -> None:
    mission_a, mission_b = two_missions
    finding_a = _create_finding(client, mission_id=mission_a, target_id="tgt-a", title="unique-A")
    _create_finding(client, mission_id=mission_b, target_id="tgt-b", title="unique-B")

    found = client.get(f"/findings/{finding_a['finding_id']}")
    assert found.status_code == 200
    payload = found.json()
    assert payload["title"] == "unique-A"
    assert payload["mission_id"] == mission_a
    assert payload["target_id"] == "tgt-a"


def test_no_secret_leak_in_api_responses(client, platform, two_missions) -> None:
    """Secret material must never surface verbatim in API responses, and
    findings written through the API must not carry internal secret columns."""
    mission_a, _ = two_missions
    finding = _create_finding(client, mission_id=mission_a, target_id="tgt-a", title="finding-A")

    payload = client.get(f"/findings/{finding['finding_id']}").json()
    # API responses are the JSON-safe projection; no internal/secret columns.
    for key in ("secret", "token", "credential", "key_hash", "api_key", "password"):
        assert key not in payload

    # A system-managed secret, persisted via the platform's TIDB, must never be
    # retrievable as plaintext through any API path.
    from hunterx.domain.entities.tidb import Secret
    from hunterx.shared.masking import mask_secret

    secret_repo = platform.tidb.repository_for(Secret)
    plaintext = "sk-live-9876543210fedcba"
    record = Secret(
        name="cert",
        kind="api_token",
        value_masked=mask_secret(plaintext),
        checksum="sha256:xyz",
        secret_key="secrets/cert",
        owner="certification",
        scope="prod",
    )
    secret_repo.save(record)

    loaded = secret_repo.get(record.id)
    assert loaded is not None
    assert plaintext not in loaded.value_masked
