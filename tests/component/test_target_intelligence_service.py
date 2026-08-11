# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Component tests for the TargetIntelligenceService application layer.

Exercises the service against the in-memory TIDB repository factory: target
registration, observation ingestion, cycle persistence, TIDB persistence of
all normalized entities, and the query service read-back.
"""

from __future__ import annotations

from hunterx.application.target_intelligence import TargetIntelligenceQueryService, TargetIntelligenceService
from hunterx.domain.entities.tidb.target_intelligence import (
    CoverageRecord,
    HypothesisRecord,
    InformationGapRecord,
    IntelligenceActionRecord,
    IntelligenceAssetRecord,
    IntelligenceDecisionRecord,
    IntelligenceEvidenceRecord,
    IntelligenceScoreRecord,
    IntelligenceTargetRecord,
    NegativeResultRecord,
    ObservationRecord,
    TargetHistoryRecord,
)
from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    IntelligenceTargetKind,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceAsset,
    IntelligenceEvidence,
    IntelligenceTarget,
    Observation,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory


def _target() -> IntelligenceTarget:
    return IntelligenceTarget(
        target_id="tgt-1",
        mission_id="mis-1",
        scope="example.com",
        identity="Example",
        kind=IntelligenceTargetKind.DOMAIN,
        value="example.com",
    )


def _obs(**overrides: object) -> Observation:
    values: dict[str, object] = {
        "target_id": "tgt-1",
        "mission_id": "mis-1",
        "tool": "httpx",
        "capability": "technology_fingerprint",
        "observation_type": ObservationType.TECHNOLOGY,
        "value": "nginx",
        "asset_key": "hostname:www.example.com",
    }
    values.update(overrides)
    return Observation(**values)  # type: ignore[arg-type]


class TestTargetIntelligenceService:
    def _service(self) -> tuple[TargetIntelligenceService, InMemoryTidbRepositoryFactory]:
        stores = InMemoryTidbRepositoryFactory()
        service = TargetIntelligenceService(stores=stores)
        return service, stores

    def test_register_target_persists(self) -> None:
        service, stores = self._service()
        service.register_target(_target())
        records = stores.repository_for(IntelligenceTargetRecord).list_by("target_id", "tgt-1", limit=1)
        assert len(records) == 1
        assert records[0].kind == "domain"

    def test_ingest_observations_persists_records_and_assets(self) -> None:
        service, stores = self._service()
        service.register_target(_target())
        service.ingest_observations(_target(), [_obs()])
        obs_records = list(stores.repository_for(ObservationRecord).stream())
        assert len(obs_records) == 1
        asset_records = list(stores.repository_for(IntelligenceAssetRecord).stream())
        assert asset_records
        coverage_records = list(stores.repository_for(CoverageRecord).stream())
        assert coverage_records

    def test_ingest_evidence_persists(self) -> None:
        service, stores = self._service()
        service.register_target(_target())
        service.ingest_evidence(
            _target(),
            [
                IntelligenceEvidence(
                    target_id="tgt-1",
                    mission_id="mis-1",
                    what="banner revealed nginx",
                    where="https://example.com/",
                    source="httpx",
                )
            ],
        )
        assert len(list(stores.repository_for(IntelligenceEvidenceRecord).stream())) == 1

    def test_run_cycle_persists_all_derived_entities(self) -> None:
        service, stores = self._service()
        target = _target()
        service.register_target(target)
        service.ingest_assets(
            target,
            [
                IntelligenceAsset(
                    target_id="tgt-1",
                    mission_id="mis-1",
                    kind=EntityKind.URL,
                    name="https://example.com/api/search",
                    properties={"parameters": ["q"]},
                )
            ],
        )
        state, actions, decision = service.run_cycle(target, mission_objective="find vulns")
        target_records = stores.repository_for(IntelligenceTargetRecord).list_by("target_id", "tgt-1", limit=1)
        assert len(target_records) == 1
        assert stores.repository_for(IntelligenceActionRecord).count() == len(actions)
        assert stores.repository_for(IntelligenceDecisionRecord).count() == 1
        assert stores.repository_for(HypothesisRecord).count() == len(state.hypotheses)
        assert stores.repository_for(InformationGapRecord).count() == len(state.gaps)
        assert stores.repository_for(CoverageRecord).count() == len(state.coverage.entries)
        assert stores.repository_for(IntelligenceScoreRecord).count() == 1

    def test_record_negative_persists_and_updates_coverage(self) -> None:
        service, stores = self._service()
        target = _target()
        service.register_target(target)
        from hunterx.domain.target_intelligence.models import NegativeResult

        service.record_negative(
            target,
            NegativeResult(
                target_id="tgt-1",
                asset_key="url:https://example.com/api/search?q=x",
                tested_capability=CoverageCapability.XSS,
                tool="dalfox",
            ),
        )
        assert stores.repository_for(NegativeResultRecord).count() == 1
        assert stores.repository_for(TargetHistoryRecord).count() == 1
        coverage = stores.repository_for(CoverageRecord).stream()
        assert any(record.capability == "xss" for record in coverage)


class TestTargetIntelligenceQueryService:
    def _setup(self) -> tuple[TargetIntelligenceService, TargetIntelligenceQueryService, InMemoryTidbRepositoryFactory]:
        stores = InMemoryTidbRepositoryFactory()
        service = TargetIntelligenceService(stores=stores)
        query = TargetIntelligenceQueryService(stores=stores)
        return service, query, stores

    def test_queries_read_back_persisted_state(self) -> None:
        service, query, _ = self._setup()
        target = _target()
        service.register_target(target)
        service.ingest_observations(target, [_obs()])
        service.run_cycle(target, mission_objective="find vulns")

        assert query.get_target("tgt-1") is not None
        assert query.assets(target_id="tgt-1")
        assert query.observations(target_id="tgt-1")
        assert query.coverage_matrix("tgt-1").entries
        assert query.actions("tgt-1")
        assert query.score("tgt-1") is not None

    def test_history_and_changes_roundtrip(self) -> None:
        service, query, _ = self._setup()
        target = _target()
        service.register_target(target)
        service.ingest_assets(
            target,
            [IntelligenceAsset(target_id="tgt-1", mission_id="mis-1", kind=EntityKind.HOSTNAME, name="www.example.com")],
        )
        changes = service.detect_changes(target)
        assert changes
        assert query.changes("tgt-1")
        assert query.history("tgt-1")
