# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Backup / restore smoke test (Sprint 034.3 §24).

No dedicated backup tooling ships with HunterX v7 (recorded as technical
debt). This smoke test verifies the durability contract that any restore path
must preserve: targets, missions, evidence, findings, proofs and relationships
survive a database close/reopen cycle on a file-backed store.
"""

from __future__ import annotations

import pytest

from hunterx.config.settings import DatabaseSettings
from hunterx.domain.entities.tidb import (
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceEvidenceRecord,
    IntelligenceTargetRecord,
    TopologyRelationship,
    VulnerabilityProof,
)
from hunterx.infrastructure.db.sql.crud import SqlTidbRepositoryFactory
from hunterx.infrastructure.db.sql.factory import SessionFactory

pytest.importorskip("sqlalchemy")


def _populate(factory) -> dict[str, str]:
    ids: dict[str, str] = {}
    target = IntelligenceTargetRecord(target_id="tgt-backup", value="backup.example.com")
    factory.repository_for(IntelligenceTargetRecord).save(target)
    ids["target"] = target.id

    asset = IntelligenceAssetRecord(asset_id="a-backup", target_id="tgt-backup", asset_key="domain:backup.example.com")
    factory.repository_for(IntelligenceAssetRecord).save(asset)
    ids["asset"] = asset.id

    evidence = IntelligenceEvidenceRecord(
        evidence_id="ev-backup", target_id="tgt-backup", mission_id="mis-backup", what="backup evidence", source="tool", tool="tool"
    )
    factory.repository_for(IntelligenceEvidenceRecord).save(evidence)
    ids["evidence"] = evidence.id

    finding = FindingRecord(finding_id="F-backup", mission_id="mis-backup", target_id="tgt-backup", title="SQLi", evidence_refs=[evidence.evidence_id])
    factory.repository_for(FindingRecord).save(finding)
    ids["finding"] = finding.id

    proof = VulnerabilityProof(proof_id="P-backup", finding_id="F-backup", mission_id="mis-backup", target_id="tgt-backup", proof_status="proven", evidence_ids=[evidence.evidence_id])
    factory.repository_for(VulnerabilityProof).save(proof)
    ids["proof"] = proof.id

    relationship = TopologyRelationship(
        rel_type="affects",
        source_entity="finding",
        source_key="F-backup",
        target_entity="asset",
        target_key="domain:backup.example.com",
        sources=["engine"],
        mission_id="mis-backup",
        relationship_key="F-backup->domain:backup.example.com",
    )
    factory.repository_for(TopologyRelationship).save(relationship)
    ids["relationship"] = relationship.id
    return ids


def test_data_survives_close_and_reopen(tmp_path) -> None:
    db_path = tmp_path / "backup.db"
    url = f"sqlite:///{db_path}"

    factory = SessionFactory(DatabaseSettings(url=url))
    factory.create_all()
    store = SqlTidbRepositoryFactory(factory)
    ids = _populate(store)
    factory.dispose()  # close the database (durability point)

    # Reopen the same file with a fresh engine — the restore-equivalent.
    reopened = SessionFactory(DatabaseSettings(url=url))
    reopened.create_all()
    try:
        store2 = SqlTidbRepositoryFactory(reopened)

        assert store2.repository_for(IntelligenceTargetRecord).get(ids["target"]) is not None
        assert store2.repository_for(IntelligenceAssetRecord).get(ids["asset"]) is not None
        assert store2.repository_for(IntelligenceEvidenceRecord).get(ids["evidence"]) is not None

        finding = store2.repository_for(FindingRecord).get(ids["finding"])
        assert finding is not None and finding.title == "SQLi"
        assert finding.evidence_refs == ["ev-backup"]

        proof = store2.repository_for(VulnerabilityProof).get(ids["proof"])
        assert proof is not None and proof.evidence_ids == ["ev-backup"]
        assert proof.finding_id == "F-backup"

        relationship = store2.repository_for(TopologyRelationship).get(ids["relationship"])
        assert relationship is not None and relationship.rel_type == "affects"
    finally:
        reopened.dispose()


def test_relationship_references_survive_restore(tmp_path) -> None:
    """Cross-entity references (evidence → finding → proof → relationship) stay
    intact after a reopen."""
    db_path = tmp_path / "backup2.db"
    url = f"sqlite:///{db_path}"
    factory = SessionFactory(DatabaseSettings(url=url))
    factory.create_all()
    store = SqlTidbRepositoryFactory(factory)
    ids = _populate(store)
    factory.dispose()

    reopened = SessionFactory(DatabaseSettings(url=url))
    reopened.create_all()
    try:
        store2 = SqlTidbRepositoryFactory(reopened)
        evidence = store2.repository_for(IntelligenceEvidenceRecord).get(ids["evidence"])
        finding = store2.repository_for(FindingRecord).get(ids["finding"])
        proof = store2.repository_for(VulnerabilityProof).get(ids["proof"])
        relationship = store2.repository_for(TopologyRelationship).get(ids["relationship"])
        assert evidence is not None and finding is not None and proof is not None
        assert relationship is not None
        assert finding.evidence_refs == [evidence.evidence_id]
        assert proof.evidence_ids == [evidence.evidence_id]
        assert proof.finding_id == finding.finding_id
    finally:
        reopened.dispose()
