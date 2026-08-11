# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the JavaScript intelligence capability.

Exercises the full wiring through the assembled platform: the JavaScript
service and query service registered in the container, the JavaScript analyzer
available on the execution engine and TIP, and an end-to-end JavaScript
intelligence run over in-memory script content with persisted assets, endpoints
and secrets.
"""

from __future__ import annotations

from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceAsset as TidbJSAsset,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceEndpoint as TidbJSEndpoint,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceRun as TidbJSRun,
)
from hunterx.domain.entities.tidb.javascript_intelligence import (
    JSIntelligenceSecret as TidbJSSecret,
)
from hunterx.platform.assembler import build_platform

_SAMPLE = 'fetch("https://api.example.com/users"); localStorage.setItem("token","abc"); const k="AKIAABCDEFGHIJKLMNOP";'


class TestPlatformJavaScript:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.javascript_service is not None
        assert platform.javascript_query_service is not None
        assert platform.has(type(platform.javascript_service))
        assert platform.resolve(type(platform.javascript_service)) is platform.javascript_service

    def test_tools_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        assert platform.execution_engine.adapter_for("javascript") is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert "javascript" in set(ids)

    def test_end_to_end_javascript_roundtrip(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("javascript", lambda _tid, _version: "1.0.0")
        engine.install("javascript", version="1.0.0")

        batch = platform.javascript_service.run(
            mission_id="int-js-mission",
            target="https://example.com",
            parameters={
                "assets": [
                    {
                        "content": _SAMPLE,
                        "url": "https://example.com/app.js",
                        "content_hash": "h1",
                    }
                ]
            },
        )
        assert batch.asset_count() == 1
        assert batch.endpoint_count() >= 1
        assert batch.secret_count() >= 1
        assert platform.tidb.repository_for(TidbJSAsset).count() == 1
        assert platform.tidb.repository_for(TidbJSEndpoint).count() == batch.endpoint_count()
        assert platform.tidb.repository_for(TidbJSSecret).count() == batch.secret_count()
        assert platform.tidb.repository_for(TidbJSRun).count() == 1

        assert len(platform.javascript_query_service.assets(host="https://example.com")) == 1
        assert (
            len(platform.javascript_query_service.endpoints(host="https://example.com"))
            == batch.endpoint_count()
        )
        assert len(platform.javascript_query_service.secrets(host="https://example.com")) == 1
        executions = platform.javascript_query_service.executions(target="https://example.com")
        assert executions and executions[0]["target_key"] == "https://example.com"
