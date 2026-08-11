# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the authentication intelligence capability.

Exercises the full wiring through the assembled platform: the auth service and
query service registered in the container, the auth-analysis tool available on
the execution engine and TIP, and an end-to-end analysis run with persisted
authentication intelligence, topology integration and events.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.entities.tidb.auth_intelligence import (
    AuthRun as TidbAuthRun,
)
from hunterx.domain.entities.tidb.auth_intelligence import AuthSurface as TidbAuthSurface
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).parent.parent / "golden" / "auth"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


class TestPlatformAuth:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.auth_service is not None
        assert platform.auth_query_service is not None
        assert platform.has(type(platform.auth_service))
        assert platform.resolve(type(platform.auth_service)) is platform.auth_service

    def test_tool_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        assert platform.execution_engine.adapter_for("auth-analysis") is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert "auth-analysis" in ids

    def test_end_to_end_auth_roundtrip(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("auth-analysis", lambda _tid, _version: "1.0.0")
        engine.install("auth-analysis", version="1.0.0")

        batch = platform.auth_service.run(
            mission_id="int-auth-mission",
            target="https://acme.com/login",
            mode="passive",
            parameters={"auth_input": _golden("login_page_input.json")},
        )
        assert batch.surface_count() >= 1
        assert batch.endpoint_count() >= 1

        assert platform.tidb.repository_for(TidbAuthSurface).count() >= 1
        assert platform.tidb.repository_for(TidbAuthRun).count() == 1
        assert platform.tidb.repository_for(TopologyRelationship).count() > 0

        summary = platform.auth_query_service.summary(mission_id="int-auth-mission")
        assert summary["surfaces"] >= 1
        assert summary["cookies"] >= 1
        assert summary["token_storage"] >= 1

    def test_oidc_roundtrip_with_identity_provider(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("auth-analysis", lambda _tid, _version: "1.0.0")
        engine.install("auth-analysis", version="1.0.0")

        platform.auth_service.run(
            mission_id="int-oidc",
            target="https://acme.com/oauth/callback",
            mode="passive",
            parameters={"auth_input": _golden("oidc_callback_input.json")},
        )
        idps = platform.auth_query_service.identity_providers(mission_id="int-oidc")
        assert idps, "an identity provider must be persisted"
        assert any("auth.acme.com" in idp.get("issuer", "") for idp in idps)
