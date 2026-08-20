# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Universal discovery — domain layer tests.

Pure data-contract coverage: stage/state/layer enums, canonical assets with
provenance, canonicalization + deduplication, and the declarative stage plan
(provider tool ids are injected from the registries by the application layer —
the domain never hardcodes a provider list).
"""

from __future__ import annotations

import pytest

from hunterx.domain.discovery.canonical import (
    DiscoveryDeduper,
    asset_key,
    canonical_host,
    canonical_host_port,
    canonical_ip,
    canonical_port,
    canonical_url,
    host_from_url,
    is_hostname,
    is_ip,
)
from hunterx.domain.discovery.enums import DiscoveryLayer, DiscoveryStage, DiscoveryState
from hunterx.domain.discovery.models import (
    DiscoveredAsset,
    DiscoveryEvidence,
    DiscoveryProviderResult,
    DiscoveryRun,
    DiscoveryStageResult,
)
from hunterx.domain.discovery.pipeline import ProviderSpec, StageDefinition, StagePlan


class TestCanonicalization:
    def test_canonical_host_lowercases_and_strips_dot(self) -> None:
        assert canonical_host("  Example.COM. ") == "example.com"
        assert canonical_host("EXAMPLE.COM..") == "example.com"

    def test_canonical_ip_compresses(self) -> None:
        assert canonical_ip("0:0:0:0:0:0:0:1") == "::1"

    def test_canonical_port_validates(self) -> None:
        assert canonical_port("443") == 443
        with pytest.raises(ValueError):
            canonical_port(0)
        with pytest.raises(ValueError):
            canonical_port(70000)

    def test_canonical_url_normalizes(self) -> None:
        assert canonical_url("HTTPS://Example.COM:443/api/x/") == "https://example.com/api/x"
        assert canonical_url("http://example.com:80/") == "http://example.com"
        assert canonical_url("http://example.com:8080/a?q=1#frag") == "http://example.com:8080/a?q=1"

    def test_canonical_host_port(self) -> None:
        assert canonical_host_port("Example.COM", "8080") == "example.com:8080"

    def test_asset_key(self) -> None:
        assert asset_key("HOST", "Example.COM") == "host:example.com"

    def test_is_ip_and_is_hostname(self) -> None:
        assert is_ip("127.0.0.1")
        assert not is_ip("example.com")
        assert is_hostname("api.example.com")
        assert not is_hostname("127.0.0.1")
        assert not is_hostname("https://example.com/x")

    def test_host_from_url(self) -> None:
        assert host_from_url("https://API.Example.COM:8443/x") == "api.example.com"
        assert host_from_url("api.example.com") == "api.example.com"


class TestDiscoveredAsset:
    def test_asset_defaults(self) -> None:
        asset = DiscoveredAsset(kind="host", name="example.com")
        assert asset.canonical_key == "host:example.com"
        assert asset.layer is DiscoveryLayer.ASSET
        assert asset.confidence == 0.0

    def test_unknown_kind_defaults_to_surface_layer(self) -> None:
        asset = DiscoveredAsset(kind="gadget", name="x")
        assert asset.layer is DiscoveryLayer.SURFACE

    def test_asset_layer_mapping(self) -> None:
        assert DiscoveredAsset(kind="host", name="a").layer is DiscoveryLayer.ASSET
        assert DiscoveredAsset(kind="port", name="a:80").layer is DiscoveryLayer.SERVICE
        assert DiscoveredAsset(kind="parameter", name="q").layer is DiscoveryLayer.INPUT
        assert DiscoveredAsset(kind="object", name="order").layer is DiscoveryLayer.OBJECT
        assert DiscoveredAsset(kind="workflow", name="checkout").layer is DiscoveryLayer.WORKFLOW
        assert DiscoveredAsset(kind="auth_surface", name="login").layer is DiscoveryLayer.STATE

    def test_confidence_is_best_evidence(self) -> None:
        asset = DiscoveredAsset(
            kind="host",
            name="a",
            evidence=[
                DiscoveryEvidence(provider="p1", confidence=0.4),
                DiscoveryEvidence(provider="p2", confidence=0.9),
            ],
        )
        assert asset.confidence == pytest.approx(0.9)

    def test_add_evidence_recomputes_confidence(self) -> None:
        asset = DiscoveredAsset(kind="host", name="a", evidence=[DiscoveryEvidence(provider="p1", confidence=0.5)])
        asset.add_evidence(DiscoveryEvidence(provider="p2", confidence=0.8))
        assert asset.confidence == pytest.approx(0.8)
        assert len(asset.evidence) == 2

    def test_merge_keeps_first_seen_and_unions_evidence(self) -> None:
        older = DiscoveredAsset(
            kind="host",
            name="a",
            first_seen="2026-01-01T00:00:00Z",
            evidence=[DiscoveryEvidence(provider="p1", confidence=0.5)],
        )
        newer = DiscoveredAsset(
            kind="host",
            name="a",
            first_seen="2026-02-01T00:00:00Z",
            evidence=[DiscoveryEvidence(provider="p2", confidence=0.9)],
        )
        older.merge(newer)
        assert older.first_seen == "2026-01-01T00:00:00Z"
        assert len(older.evidence) == 2
        assert older.confidence == pytest.approx(0.9)

    def test_to_dict_is_json_safe(self) -> None:
        asset = DiscoveredAsset(
            kind="port",
            name="example.com:80",
            layer=DiscoveryLayer.SERVICE,
            evidence=[DiscoveryEvidence(provider="p", confidence=1.0)],
        )
        data = asset.to_dict()
        assert data["kind"] == "port"
        assert data["layer"] == "service"
        assert data["evidence"][0]["provider"] == "p"


class TestDiscoveryDeduper:
    def test_dedupes_equivalent_spellings(self) -> None:
        deduper = DiscoveryDeduper()
        deduper.add(DiscoveredAsset(kind="host", name="Example.COM"))
        deduper.add(DiscoveredAsset(kind="host", name="example.com."))
        assert deduper.stats()["unique"] == 1
        assert deduper.stats()["raw"] == 2
        assert deduper.get("host", "example.com") is not None

    def test_merge_accumulates_provenance(self) -> None:
        deduper = DiscoveryDeduper()
        deduper.add(DiscoveredAsset(kind="host", name="a", evidence=[DiscoveryEvidence(provider="p1")]))
        deduper.add(DiscoveredAsset(kind="host", name="a", evidence=[DiscoveryEvidence(provider="p2")]))
        asset = deduper.get("host", "a")
        assert asset is not None
        assert len(asset.evidence) == 2

    def test_evidence_for(self) -> None:
        deduper = DiscoveryDeduper()
        deduper.add(DiscoveredAsset(kind="host", name="a", evidence=[DiscoveryEvidence(provider="p1")]))
        assert len(deduper.evidence_for("host", "a")) == 1
        assert deduper.evidence_for("host", "missing") == []

    def test_by_kind(self) -> None:
        deduper = DiscoveryDeduper()
        deduper.add(DiscoveredAsset(kind="host", name="a"))
        deduper.add(DiscoveredAsset(kind="port", name="a:80"))
        assert len(deduper.by_kind("host")) == 1
        assert len(deduper.by_kind("port")) == 1


class TestDiscoveryRun:
    def test_run_tracks_stages_and_states(self) -> None:
        run = DiscoveryRun(target="example.com", mission_id="m1")
        assert run.run_id
        stage = DiscoveryStageResult(
            stage=DiscoveryStage.HOST,
            state=DiscoveryState.COMPLETED,
            providers=[
                DiscoveryProviderResult(provider_id="p", state=DiscoveryState.COMPLETED),
            ],
        )
        run.add_stage(stage)
        assert run.stage_state(DiscoveryStage.HOST) == "completed"
        assert run.stage_state(DiscoveryStage.PORT) == "unavailable"
        assert run.provider_states() == {"p": "completed"}
        assert run.asset_count() == 0

    def test_run_by_kind(self) -> None:
        run = DiscoveryRun(target="example.com")
        run.assets = [DiscoveredAsset(kind="host", name="a"), DiscoveredAsset(kind="port", name="a:80")]
        assert len(run.by_kind("host")) == 1

    def test_run_to_dict_is_json_safe(self) -> None:
        run = DiscoveryRun(target="example.com")
        data = run.to_dict()
        assert data["target"] == "example.com"
        assert data["run_id"] == run.run_id

    def test_provider_result_parses_state_strings(self) -> None:
        result = DiscoveryProviderResult(provider_id="p", state="unavailable")
        assert result.state is DiscoveryState.UNAVAILABLE


class TestStagePlan:
    def test_plan_exposes_stages_and_tools(self) -> None:
        definitions = (
            StageDefinition(
                stage=DiscoveryStage.DNS,
                providers=(ProviderSpec(tool_id="dnsx", kind="dns"),),
            ),
            StageDefinition(stage=DiscoveryStage.GRAPHQL, optional=True),
        )
        plan = StagePlan(stages=definitions)
        assert plan.stage(DiscoveryStage.DNS) is definitions[0]
        assert set(plan.tool_ids()) == {"dnsx"}
        stage, provider = plan.provider_for("dnsx")
        assert stage is DiscoveryStage.DNS
        assert provider.tool_id == "dnsx"

    def test_optional_stage(self) -> None:
        definition = StageDefinition(stage=DiscoveryStage.GRAPHQL, optional=True)
        assert definition.optional
        assert not StageDefinition(stage=DiscoveryStage.HTTP, optional=False).optional


class TestStageOrder:
    """The stage ordering is a fixed pipeline contract (no silent reorder)."""

    def test_stage_enum_ordering(self) -> None:
        stages = [stage.value for stage in DiscoveryStage]
        assert stages == [
            "asset",
            "dns",
            "subdomain",
            "host",
            "port",
            "service",
            "technology",
            "http",
            "api",
            "graphql",
            "javascript",
            "workflow",
            "auth",
        ]


__all__: list[str] = []