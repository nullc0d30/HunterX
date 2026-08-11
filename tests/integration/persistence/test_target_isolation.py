# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target isolation tests (Sprint 034.3 §4 — release-blocking).

TARGET-A and TARGET-B receive independent, fully populated records. The suite
verifies that TARGET-A can never retrieve TARGET-B intelligence and vice versa
through the repository layer and the application query services.
"""

from __future__ import annotations

from hunterx.application.target_intelligence import TargetIntelligenceQueryService
from hunterx.domain.entities.tidb import (
    Execution,
    FindingRecord,
    IntelligenceAssetRecord,
    IntelligenceEvidenceRecord,
    IntelligenceTargetRecord,
    ObservationRecord,
    VulnerabilityProof,
)


def _populate_target(factory, target_id: str, mission_id: str, base: str) -> None:
    factory.repository_for(IntelligenceTargetRecord).save(
        IntelligenceTargetRecord(
            target_id=target_id, mission_id=mission_id, value=base, kind="domain", tenant="tenant-x"
        )
    )
    factory.repository_for(IntelligenceAssetRecord).save_many(
        [
            IntelligenceAssetRecord(
                asset_id=f"{target_id}-a{i}",
                target_id=target_id,
                mission_id=mission_id,
                asset_key=f"domain:{base}-{i}",
                name=f"{base}-{i}",
            )
            for i in range(3)
        ]
    )
    factory.repository_for(ObservationRecord).save_many(
        [
            ObservationRecord(
                observation_id=f"{target_id}-o{i}",
                target_id=target_id,
                mission_id=mission_id,
                tool="nmap",
                value=f"port-{80 + i}",
                normalized_value=f"tcp/{80 + i}",
            )
            for i in range(5)
        ]
    )
    factory.repository_for(IntelligenceEvidenceRecord).save_many(
        [
            IntelligenceEvidenceRecord(
                evidence_id=f"{target_id}-e{i}",
                target_id=target_id,
                mission_id=mission_id,
                what=f"observed {base} {i}",
                how="scan",
                source="nmap",
                tool="nmap",
                raw_artifact_ref=f"artifacts/{target_id}/{i}.xml",
            )
            for i in range(2)
        ]
    )
    factory.repository_for(FindingRecord).save(
        FindingRecord(
            finding_id=f"{target_id}-F1",
            mission_id=mission_id,
            target_id=target_id,
            title=f"{base} finding",
            evidence_refs=[f"{target_id}-e0"],
        )
    )
    factory.repository_for(VulnerabilityProof).save(
        VulnerabilityProof(
            proof_id=f"{target_id}-P1",
            finding_id=f"{target_id}-F1",
            mission_id=mission_id,
            target_id=target_id,
            proof_type="poc",
            proof_status="proven",
        )
    )
    factory.repository_for(Execution).save(
        Execution(
            execution_id=f"{target_id}-exec1",
            mission_id=mission_id,
            target=base,
            tool_id="nmap",
            status="completed",
            parameters={"output": f"{base} scan output"},
        )
    )


def test_target_records_are_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    target_repo = backend_factory.repository_for(IntelligenceTargetRecord)
    a = target_repo.list_by("target_id", "tgt-a")
    b = target_repo.list_by("target_id", "tgt-b")
    assert {t.value for t in a} == {"acme-a.example.com"}
    assert {t.value for t in b} == {"acme-b.example.com"}
    assert {t.value for t in a}.isdisjoint({t.value for t in b})


def test_assets_are_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    repo = backend_factory.repository_for(IntelligenceAssetRecord)
    a = repo.list_by("target_id", "tgt-a")
    b = repo.list_by("target_id", "tgt-b")
    assert len(a) == 3 and len(b) == 3
    assert all(e.target_id == "tgt-a" for e in a)
    assert all(e.target_id == "tgt-b" for e in b)
    assert {e.asset_id for e in a}.isdisjoint({e.asset_id for e in b})


def test_observations_are_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    repo = backend_factory.repository_for(ObservationRecord)
    a = repo.list_by("target_id", "tgt-a")
    b = repo.list_by("target_id", "tgt-b")
    assert len(a) == 5 and len(b) == 5
    assert all(o.target_id == "tgt-a" for o in a)
    assert all(o.target_id == "tgt-b" for o in b)
    assert {o.observation_id for o in a}.isdisjoint({o.observation_id for o in b})


def test_evidence_is_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    repo = backend_factory.repository_for(IntelligenceEvidenceRecord)
    a = repo.list_by("target_id", "tgt-a")
    b = repo.list_by("target_id", "tgt-b")
    assert all(e.target_id == "tgt-a" for e in a)
    assert all(e.target_id == "tgt-b" for e in b)
    assert {e.evidence_id for e in a}.isdisjoint({e.evidence_id for e in b})


def test_findings_and_proofs_are_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    finding_repo = backend_factory.repository_for(FindingRecord)
    proof_repo = backend_factory.repository_for(VulnerabilityProof)

    fa = finding_repo.list_by("target_id", "tgt-a")
    fb = finding_repo.list_by("target_id", "tgt-b")
    assert len(fa) == 1 and len(fb) == 1
    assert fa[0].finding_id == "tgt-a-F1"
    assert fb[0].finding_id == "tgt-b-F1"

    pa = proof_repo.list_by("target_id", "tgt-a")
    pb = proof_repo.list_by("target_id", "tgt-b")
    assert pa[0].finding_id == "tgt-a-F1"
    assert pb[0].finding_id == "tgt-b-F1"


def test_tool_executions_are_isolated(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    repo = backend_factory.repository_for(Execution)
    a = repo.list_by("mission_id", "mis-a")
    b = repo.list_by("mission_id", "mis-b")
    assert len(a) == 1 and len(b) == 1
    assert a[0].execution_id == "tgt-a-exec1"
    assert b[0].execution_id == "tgt-b-exec1"
    assert a[0].target == "acme-a.example.com"
    assert b[0].target == "acme-b.example.com"


def test_service_layer_target_isolation(backend_factory) -> None:
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    query = TargetIntelligenceQueryService(stores=backend_factory)

    ta = query.get_target("tgt-a")
    tb = query.get_target("tgt-b")
    assert ta is not None and ta.value == "acme-a.example.com"
    assert tb is not None and tb.value == "acme-b.example.com"

    assets_a = query.assets(target_id="tgt-a")
    assets_b = query.assets(target_id="tgt-b")
    assert all(a.asset_id.startswith("tgt-a") for a in assets_a)
    assert all(b.asset_id.startswith("tgt-b") for b in assets_b)

    obs_a = query.observations(target_id="tgt-a")
    obs_b = query.observations(target_id="tgt-b")
    assert len(obs_a) == 5 and len(obs_b) == 5
    assert {o.observation_id for o in obs_a}.isdisjoint({o.observation_id for o in obs_b})


def test_cross_target_reference_is_never_returned(backend_factory) -> None:
    """A proof for TARGET-A must never surface when querying TARGET-B."""
    _populate_target(backend_factory, "tgt-a", "mis-a", "acme-a.example.com")
    _populate_target(backend_factory, "tgt-b", "mis-b", "acme-b.example.com")

    proof_repo = backend_factory.repository_for(VulnerabilityProof)
    for proof in proof_repo.list_by("target_id", "tgt-b"):
        assert not proof.finding_id.startswith("tgt-a")
        assert proof.target_id == "tgt-b"
