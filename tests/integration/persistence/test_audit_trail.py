# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Audit trail tests (Sprint 034.3 §21).

Important state changes (finding created/validated, mission started/paused/
resumed/completed) must be reconstructable from the append-only audit trail
with sufficient provenance.
"""

from __future__ import annotations

import pytest

from hunterx.domain.entities.tidb import (
    FindingRecord,
    IntelligenceTargetRecord,
    VulnerabilityProof,
)
from hunterx.infrastructure.db.sql.crud import SqlCrudRepository, SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.tidb_models import (
    AuditLogModel,
    ChangeHistoryModel,
    TimelineEventModel,
    VersionHistoryModel,
)

pytest.importorskip("sqlalchemy")


@pytest.fixture()
def versioned_factory(session_factory):
    from hunterx.infrastructure.db.sql.versioning import install_versioning

    install_versioning(session_factory, actor="certification", source="sprint-034.3")
    return SqlTidbRepositoryFactory(session_factory)


def _audit_rows(session_factory, model) -> list:
    from sqlalchemy import select

    with session_factory.session() as session:
        return list(session.execute(select(model)).scalars())


def test_create_writes_audit_and_history(versioned_factory, session_factory) -> None:
    repo = versioned_factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-audit", value="audit.example.com")
    repo.save(target)

    audit = _audit_rows(session_factory, AuditLogModel)
    assert any(a.action == "create" and a.object_id == target.id for a in audit)
    assert all(a.actor == "certification" for a in audit)

    versions = _audit_rows(session_factory, VersionHistoryModel)
    assert any(v.entity_id == target.id and v.reason == "create" for v in versions)

    timeline = _audit_rows(session_factory, TimelineEventModel)
    assert any(t.entity_id == target.id and t.event_type == "intelligencetargetrecord.created" for t in timeline)


def test_update_records_field_level_change_history(versioned_factory, session_factory) -> None:
    repo = versioned_factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-audit", value="before.example.com")
    repo.save(target)

    loaded = repo.get(target.id)
    assert loaded is not None
    loaded.value = "after.example.com"
    repo.save(loaded)

    changes = _audit_rows(session_factory, ChangeHistoryModel)
    value_changes = [c for c in changes if c.field_name == "value" and c.entity_id == target.id]
    assert len(value_changes) == 1
    assert value_changes[0].old_value == "before.example.com"
    assert value_changes[0].new_value == "after.example.com"
    assert value_changes[0].changed_by == "certification"

    audit = _audit_rows(session_factory, AuditLogModel)
    assert any(a.action == "update" and a.object_id == target.id for a in audit)


def test_soft_delete_is_audited(versioned_factory, session_factory) -> None:
    repo = versioned_factory.repository_for(IntelligenceTargetRecord)
    target = IntelligenceTargetRecord(target_id="tgt-audit", value="del.example.com")
    repo.save(target)
    repo.soft_delete(target.id)

    audit = _audit_rows(session_factory, AuditLogModel)
    delete_entries = [a for a in audit if a.object_id == target.id and a.action == "delete"]
    assert len(delete_entries) == 1
    assert delete_entries[0].before is not None
    assert delete_entries[0].after is not None and delete_entries[0].after.get("deleted_at")


def test_finding_lifecycle_is_reconstructable(versioned_factory, session_factory) -> None:
    repo = versioned_factory.repository_for(FindingRecord)
    finding = FindingRecord(finding_id="F-audit", target_id="tgt-1", title="SQLi", status="candidate")
    repo.save(finding)

    loaded = repo.get(finding.id)
    assert loaded is not None
    loaded.status = "validated"
    repo.save(loaded)

    proof_repo = versioned_factory.repository_for(VulnerabilityProof)
    proof = VulnerabilityProof(proof_id="P-audit", finding_id="F-audit", target_id="tgt-1", proof_status="proven")
    proof_repo.save(proof)

    audit = _audit_rows(session_factory, AuditLogModel)
    finding_events = [a for a in audit if a.object_id == finding.id]
    assert {a.action for a in finding_events} == {"create", "update"}
    proof_events = [a for a in audit if a.object_id == proof.id]
    assert {a.action for a in proof_events} == {"create"}

    # The full lifecycle can be replayed in chronological order.
    finding_events.sort(key=lambda a: a.occurred_at)
    assert finding_events[0].action == "create"
    assert finding_events[0].after["status"] == "candidate"
    assert finding_events[-1].action == "update"
    assert finding_events[-1].after["status"] == "validated"


def test_mission_lifecycle_is_audited(versioned_factory, session_factory) -> None:
    from hunterx.application.mission_orchestration import MissionOrchestrationService
    from hunterx.domain.entities.tidb import MissionOrchestrationRecord
    from hunterx.engines.mission_orchestration import MissionOrchestrationEngine

    service = MissionOrchestrationService(engine=MissionOrchestrationEngine(), stores=versioned_factory)
    mission = service.create_mission(target="https://example.com", objective="web")
    mission_id = mission.mission_id
    service.start(mission_id)
    service.pause(mission_id)
    service.resume(mission_id)
    service.finalize(mission_id)

    # The audit trail records the persisted entity by its envelope id; resolve
    # it from the mission_id scope.
    records = versioned_factory.repository_for(MissionOrchestrationRecord).list_by("mission_id", mission_id)
    assert records, "mission record must be persisted"
    record_id = records[0].id

    audit = _audit_rows(session_factory, AuditLogModel)
    mission_audit = [a for a in audit if a.object_id == record_id]
    # create (on registration) + updates for start/pause/resume/finalize.
    assert any(a.action == "create" for a in mission_audit)
    assert any(a.action == "update" for a in mission_audit)
    assert len(mission_audit) >= 5


def test_without_versioning_no_audit_is_written(session_factory) -> None:
    repo = SqlCrudRepository(session_factory, IntelligenceTargetRecord)
    repo.save(IntelligenceTargetRecord(target_id="tgt-1", value="x.example.com"))
    assert _audit_rows(session_factory, AuditLogModel) == []


def test_platform_build_wires_versioning() -> None:
    """A production-style SQL platform must install the versioning listener so
    every TIDB write is audited (Sprint 034.3 §21)."""
    from hunterx.config.settings import DatabaseSettings, Settings
    from hunterx.domain.entities.tidb import IntelligenceTargetRecord
    from hunterx.platform import build_platform

    platform = build_platform(Settings(database=DatabaseSettings(url="sqlite:///:memory:")))
    try:
        stores = platform.tidb
        repo = stores.repository_for(IntelligenceTargetRecord)
        target = IntelligenceTargetRecord(target_id="tgt-wired", value="wired.example.com")
        repo.save(target)

        session_factory = platform.repositories["session_factory"]
        audit = _audit_rows(session_factory, AuditLogModel)
        assert any(a.action == "create" and a.object_id == target.id for a in audit)
    finally:
        session_factory = platform.repositories.get("session_factory")
        if session_factory is not None:
            session_factory.dispose()
