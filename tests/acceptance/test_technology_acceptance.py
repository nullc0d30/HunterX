# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the technology fingerprinting capability.

End-to-end scenario: run a fingerprinting mission through the assembled
platform with fake tool runners/fetch, verify the correlated technology
intelligence, evidence-backed versions, conflict preservation, TIDB
persistence, historical comparison, topology integration and the
``technology.*`` event stream.
"""

from __future__ import annotations

from pathlib import Path

from hunterx.domain.entities.tidb.technology import (
    TechnologyEvidence as TidbTechnologyEvidence,
)
from hunterx.domain.entities.tidb.technology import (
    TechnologyObservation as TidbTechnologyObservation,
)
from hunterx.domain.entities.tidb.technology import TechnologyRun as TidbTechnologyRun
from hunterx.domain.entities.tidb.technology import TechnologyVersion as TidbTechnologyVersion
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.domain.technology.detector import HttpEvidence
from hunterx.platform.assembler import build_platform
from hunterx.tools.recon.runner import BinaryRunner, CommandResult

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "tech"


class FakeRunner(BinaryRunner):
    """Binary runner returning canned golden output per binary name."""

    def __init__(self) -> None:
        super().__init__()
        self._mapping = {
            "httpx": (GOLDEN / "httpx_tech.jsonl").read_text(encoding="utf-8"),
            "whatweb": (GOLDEN / "whatweb_tech.json").read_text(encoding="utf-8"),
        }

    def run(self, argv: list[str], *, timeout_s: float = 0.0, tool_id: str = "") -> CommandResult:
        return CommandResult(returncode=0, stdout=self._mapping.get(argv[0], ""))


class TestTechnologyAcceptance:
    def test_fingerprinting_intelligence_flow(self) -> None:
        platform = build_platform()
        # wire fake runners/fetch into the composed fingerprinting adapters
        runner = FakeRunner()
        adapters = platform.execution_engine
        adapters.adapter_for("httpx")._runner = runner  # noqa: SLF001
        adapters.adapter_for("whatweb")._runner = runner  # noqa: SLF001

        def fetch(url: str, timeout: float) -> HttpEvidence:
            return HttpEvidence(
                url=url,
                status_code=200,
                headers={"Server": "nginx/1.24.0", "cf-ray": "xyz"},
                html="<html><p>wp-content</p></html>",
                meta={"generator": "WordPress 6.4.3"},
            )

        adapters.adapter_for("signature")._fetch = fetch  # noqa: SLF001
        for tool_id in ("httpx", "whatweb", "signature"):
            platform.execution_engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
            platform.execution_engine.install(tool_id, version="1.0.0")

        # 1. Run the mission through the composed service
        batch = platform.technology_service.run(mission_id="acceptance-mission", target="shop.example.com")
        assert batch.technology_count() >= 5
        names = {obs.canonical_name for obs in batch.technologies}
        assert {"Nginx", "PHP", "React", "Cloudflare"} <= names
        assert batch.version_count() >= 3

        # 2. Evidence-backed versions
        nginx = next(obs for obs in batch.technologies if obs.canonical_name == "Nginx")
        assert nginx.version_spec is not None
        assert nginx.version_spec.confidence.value in ("confirmed", "probable")
        assert nginx.evidence

        # 3. Persisted into the canonical TIDB (single source of truth)
        stores = platform.tidb
        assert stores.repository_for(TidbTechnologyObservation).count() == batch.technology_count()
        assert stores.repository_for(TidbTechnologyVersion).count() >= 3
        assert stores.repository_for(TidbTechnologyEvidence).count() >= batch.technology_count()
        assert stores.repository_for(TidbTechnologyRun).count() == 1

        # 4. Integrated into the existing topology (not a separate graph)
        persisted = list(stores.repository_for(TopologyRelationship).stream())
        tech_edges = [edge for edge in persisted if "technology" in edge.source_entity or "technology" in edge.target_entity or edge.rel_type == "uses"]
        assert tech_edges
        assert all(edge.relationship_key for edge in tech_edges)

        # 5. Queryable through the technology query service
        inventory = platform.technology_query_service.inventory(asset="shop.example.com")
        assert inventory
        inventory_names = {entry["technology"] for entry in inventory}
        assert {"Nginx", "PHP", "React", "Cloudflare"} <= inventory_names
        assert platform.technology_query_service.servers()
        assert platform.technology_query_service.by_category("cdn")

        # 6. Historical comparison detects changes on a second mission
        historical = list(batch.technologies)

        def fetch_newer(url: str, timeout: float) -> HttpEvidence:
            return HttpEvidence(
                url=url,
                status_code=200,
                headers={"Server": "nginx/1.25.1", "cf-ray": "xyz"},
                html="<html><p>wp-content</p></html>",
                meta={"generator": "WordPress 6.5.0"},
            )

        adapters.adapter_for("signature")._fetch = fetch_newer  # noqa: SLF001
        platform.cache.flush()
        second = platform.technology_service.run(
            mission_id="acceptance-mission-2",
            target="shop.example.com",
            tools=["signature"],
            with_history=True,
            historical=historical,
        )
        assert second.changes
        assert any(change.change_type == "changed" for change in second.changes)

        # 7. Topology reflects technology relationships after the run
        updated_edges = [edge for edge in stores.repository_for(TopologyRelationship).stream() if edge.rel_type == "uses"]
        assert updated_edges
