# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for the technology fingerprinting capability.

Exercises the full wiring through the assembled platform: the fingerprinting
service and query service registered in the container, the fingerprinting
tools (httpx, whatweb, signature) available on the execution engine and TIP,
and an end-to-end fingerprinting run over golden tool output with persisted
technology intelligence and topology integration.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.domain.entities.tidb.technology import TechnologyObservation as TidbTechnologyObservation
from hunterx.domain.entities.tidb.technology import TechnologyRun as TidbTechnologyRun
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.domain.technology.detector import HttpEvidence
from hunterx.platform.assembler import build_platform
from hunterx.tools.recon.runner import BinaryRunner, CommandResult

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "tech"


class FakeRunner(BinaryRunner):
    """Binary runner returning canned golden output per binary name."""

    def run(self, argv: list[str], *, timeout_s: float = 0.0, tool_id: str = "") -> CommandResult:
        mapping = {
            "httpx": (GOLDEN / "httpx_tech.jsonl").read_text(encoding="utf-8"),
            "whatweb": (GOLDEN / "whatweb_tech.json").read_text(encoding="utf-8"),
        }
        return CommandResult(returncode=0, stdout=mapping.get(argv[0], ""))


class TestPlatformTechnology:
    def test_services_resolvable_from_platform(self) -> None:
        platform = build_platform()
        assert platform.technology_service is not None
        assert platform.technology_query_service is not None
        assert platform.has(type(platform.technology_service))
        assert platform.resolve(type(platform.technology_service)) is platform.technology_service

    def test_tools_registered_on_engine_and_tip(self) -> None:
        platform = build_platform()
        for tool_id in ("httpx", "whatweb", "signature"):
            assert platform.execution_engine.adapter_for(tool_id) is not None
        ids = [tool.tool_id for tool in platform.tip.list_tools()]
        assert {"httpx", "whatweb", "signature"} <= set(ids)

    def test_end_to_end_fingerprint_roundtrip(self) -> None:
        platform = build_platform()
        runner = FakeRunner()
        engine = platform.execution_engine
        engine.adapter_for("httpx")._runner = runner  # noqa: SLF001
        engine.adapter_for("whatweb")._runner = runner  # noqa: SLF001
        engine.adapter_for("signature")._fetch = (  # noqa: SLF001
            lambda url, timeout: HttpEvidence(
                url=url,
                status_code=200,
                headers={"Server": "nginx/1.24.0", "cf-ray": "xyz"},
                html="<html><p>wp-content</p></html>",
                meta={"generator": "WordPress 6.4.3"},
            )
        )
        for tool_id in ("httpx", "whatweb", "signature"):
            engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
            engine.install(tool_id, version="1.0.0")

        batch = platform.technology_service.run(mission_id="int-mission", target="shop.example.com")
        assert batch.technology_count() >= 5
        assert platform.tidb.repository_for(TidbTechnologyObservation).count() == batch.technology_count()
        assert platform.tidb.repository_for(TidbTechnologyRun).count() == 1
        uses_edges = [
            edge
            for edge in platform.tidb.repository_for(TopologyRelationship).stream()
            if edge.rel_type == "uses"
        ]
        assert uses_edges

        inventory = platform.technology_query_service.inventory(asset="shop.example.com")
        assert len(inventory) == batch.technology_count()
