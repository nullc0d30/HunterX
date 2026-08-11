# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: cloud & SaaS intelligence wired into the platform."""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudProvider as TidbCloudProvider,
)
from hunterx.domain.entities.tidb.cloud_intelligence import CloudRun as TidbCloudRun
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.platform.assembler import build_platform

GOLDEN = Path(__file__).parent.parent / "golden" / "cloud"


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


class TestCloudPlatform:
    def test_platform_exposes_cloud_services(self) -> None:
        platform = build_platform()
        assert platform.cloud_service is not None
        assert platform.cloud_query_service is not None
        assert platform.has(type(platform.cloud_service))
        assert platform.resolve(type(platform.cloud_service)) is platform.cloud_service
        assert platform.execution_engine.adapter_for("cloud-analysis") is not None
        assert "cloud-analysis" in [tool.tool_id for tool in platform.tip.list_tools()]

    def test_cloud_mission_end_to_end(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
        engine.install("cloud-analysis", version="1.0.0")
        batch = platform.cloud_service.run(
            mission_id="int-cloud-mission",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        assert batch.provider_count() >= 1
        assert platform.tidb.repository_for(TidbCloudProvider).count() >= 1
        assert platform.tidb.repository_for(TidbCloudRun).count() == 1
        assert platform.tidb.repository_for(TopologyRelationship).count() > 0

    def test_cloud_query_service_reports(self) -> None:
        platform = build_platform()
        engine = platform.execution_engine
        engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
        engine.install("cloud-analysis", version="1.0.0")
        platform.cloud_service.run(
            mission_id="int-cloud-mission",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        summary = platform.cloud_query_service.summary(mission_id="int-cloud-mission")
        assert summary["providers"] >= 1
        assert summary["services"] >= 1
        assert platform.cloud_query_service.providers(mission_id="int-cloud-mission")
        assert platform.cloud_query_service.runs(mission_id="int-cloud-mission")
