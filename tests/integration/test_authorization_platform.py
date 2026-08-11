# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the authorization intelligence capability.

Exercises the full wiring through the assembled platform: the authorization
service and query service registered in the container, the
authorization-analysis tool available on the execution engine and TIP, and an
end-to-end analysis run with persisted authorization intelligence, topology
integration and events.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationResource as TidbAuthorizationResource,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRole as TidbAuthorizationRole,
)
from hunterx.domain.entities.tidb.authorization_intelligence import (
    AuthorizationRun as TidbAuthorizationRun,
)
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).parent.parent / "golden" / "authorization"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


class TestPlatformAuthorization:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.authorization_service is not None
        assert platform.authorization_query_service is not None
        assert platform.has(type(platform.authorization_service))
        assert platform.resolve(type(platform.authorization_service)) is platform.authorization_service

    def test_tool_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        assert platform.execution_engine.adapter_for("authorization-analysis") is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert "authorization-analysis" in ids

    def test_end_to_end_authorization_roundtrip(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("authorization-analysis", lambda _tid, _version: "1.0.0")
        engine.install("authorization-analysis", version="1.0.0")

        batch = platform.authorization_service.run(
            mission_id="int-authz-mission",
            target="https://acme.com/admin",
            mode="passive",
            parameters={"authorization_input": _golden("admin_rbac_api.json")},
        )
        assert batch.resource_count() >= 1
        assert batch.role_count() >= 1

        assert platform.tidb.repository_for(TidbAuthorizationResource).count() >= 1
        assert platform.tidb.repository_for(TidbAuthorizationRole).count() >= 1
        assert platform.tidb.repository_for(TidbAuthorizationRun).count() == 1
        assert platform.tidb.repository_for(TopologyRelationship).count() > 0

        summary = platform.authorization_query_service.summary(mission_id="int-authz-mission")
        assert summary["resources"] >= 1
        assert summary["roles"] >= 1
        assert summary["admin_surfaces"] >= 1

    def test_tenant_roundtrip_with_roles(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("authorization-analysis", lambda _tid, _version: "1.0.0")
        engine.install("authorization-analysis", version="1.0.0")

        platform.authorization_service.run(
            mission_id="int-authz-tenant",
            target="https://saas.example.com",
            mode="passive",
            parameters={"authorization_input": _golden("tenant_rebac_app.json")},
        )
        roles = platform.authorization_query_service.roles(mission_id="int-authz-tenant")
        assert roles, "roles must be persisted"
        assert any("admin" in role.get("name", "") for role in roles)
