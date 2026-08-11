# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence provenance tests (Sprint 034.3 §6).

Every evidence object must answer WHO/WHAT produced it, WHICH TOOL, WHICH
EXECUTION, WHICH TARGET, WHICH MISSION, WHEN, and link back to its raw artifact,
normalized observation, finding and proof. Provenance must survive
persistence/retrieval.
"""

from __future__ import annotations

from hunterx.domain.entities.tidb import (
    Execution,
    FindingRecord,
    IntelligenceEvidenceRecord,
    ObservationRecord,
    VulnerabilityProof,
)


def _full_provenance_evidence() -> IntelligenceEvidenceRecord:
    return IntelligenceEvidenceRecord(
        evidence_id="ev-provenance-1",
        target_id="tgt-prov",
        mission_id="mis-prov",
        asset_key="domain:example.com",
        what="HTTP response revealed a reflected XSS sink in the search parameter",
        where="https://example.com/search?q=1",
        when="2026-08-10T10:00:00+00:00",
        how="parameter fuzzing with reflected payload",
        source="dalfox",
        why_trust="the response was captured over two independent replays",
        reproducibility="reproducible",
        tool="dalfox",
        tool_version="2.9.3",
        command_configuration={"payload": "<script>alert(1)</script>", "scope": "example.com"},
        raw_artifact_ref="artifacts/mis-prov/dalfox/run-42.xml",
        parser_version="1.2.0",
        normalizer_version="1.1.0",
        confidence=0.95,
        meta={"environment": "certification"},
    )


def test_full_provenance_survives_sql_roundtrip(sql_factory) -> None:
    repo = sql_factory.repository_for(IntelligenceEvidenceRecord)
    evidence = _full_provenance_evidence()
    repo.save(evidence)

    loaded = repo.get(evidence.id)
    assert loaded is not None
    assert loaded.id == evidence.id
    assert loaded.evidence_id == "ev-provenance-1"
    assert loaded.target_id == "tgt-prov"
    assert loaded.mission_id == "mis-prov"
    assert loaded.asset_key == "domain:example.com"
    assert loaded.what == "HTTP response revealed a reflected XSS sink in the search parameter"
    assert loaded.where == "https://example.com/search?q=1"
    assert loaded.when == "2026-08-10T10:00:00+00:00"
    assert loaded.how == "parameter fuzzing with reflected payload"
    assert loaded.source == "dalfox"
    assert loaded.why_trust == "the response was captured over two independent replays"
    assert loaded.reproducibility == "reproducible"
    assert loaded.tool == "dalfox"
    assert loaded.tool_version == "2.9.3"
    assert loaded.command_configuration == {"payload": "<script>alert(1)</script>", "scope": "example.com"}
    assert loaded.raw_artifact_ref == "artifacts/mis-prov/dalfox/run-42.xml"
    assert loaded.parser_version == "1.2.0"
    assert loaded.normalizer_version == "1.1.0"
    assert loaded.confidence == 0.95
    assert loaded.meta == {"environment": "certification"}


def test_full_provenance_survives_memory_roundtrip(memory_factory) -> None:
    repo = memory_factory.repository_for(IntelligenceEvidenceRecord)
    evidence = _full_provenance_evidence()
    repo.save(evidence)

    loaded = repo.get(evidence.id)
    assert loaded is not None
    assert loaded.evidence_id == "ev-provenance-1"
    assert loaded.tool == "dalfox"
    assert loaded.tool_version == "2.9.3"
    assert loaded.raw_artifact_ref == "artifacts/mis-prov/dalfox/run-42.xml"
    assert loaded.command_configuration == {"payload": "<script>alert(1)</script>", "scope": "example.com"}
    assert loaded.target_id == "tgt-prov"
    assert loaded.mission_id == "mis-prov"


def test_observation_to_evidence_to_finding_to_proof_chain(backend_factory) -> None:
    """The evidence chain stays intact across persistence: observation →
    evidence (links raw artifact) → finding (evidence_refs) → proof
    (evidence_ids) → impact."""
    obs_repo = backend_factory.repository_for(ObservationRecord)
    ev_repo = backend_factory.repository_for(IntelligenceEvidenceRecord)
    finding_repo = backend_factory.repository_for(FindingRecord)
    proof_repo = backend_factory.repository_for(VulnerabilityProof)
    exec_repo = backend_factory.repository_for(Execution)

    execution = Execution(
        execution_id="exec-prov-1",
        mission_id="mis-prov",
        tool_id="nuclei",
        status="completed",
        parameters={"stdout": "nuclei finding output"},
    )
    observation = ObservationRecord(
        observation_id="obs-prov-1",
        target_id="tgt-prov",
        mission_id="mis-prov",
        tool="nuclei",
        tool_version="3.2.0",
        timestamp="2026-08-10T10:05:00+00:00",
        observation_type="vulnerability_scan",
        value="CVE-2024-1234 detected",
        normalized_value="ssrf",
        source="nuclei",
        provenance={"template": "CVE-2024-1234", "host": "example.com"},
        raw_artifact_ref="artifacts/mis-prov/nuclei/out.json",
        evidence_ref="ev-prov-1",
        dedup_key="ssrf|example.com",
    )
    evidence = _full_provenance_evidence()
    evidence.evidence_id = "ev-prov-1"
    evidence.raw_artifact_ref = "artifacts/mis-prov/nuclei/out.json"
    evidence.source = "nuclei"
    finding = FindingRecord(
        finding_id="F-prov",
        mission_id="mis-prov",
        target_id="tgt-prov",
        title="SSRF",
        status="validated",
        observations=[{"observation_id": "obs-prov-1", "value": "CVE-2024-1234 detected"}],
        evidence_refs=["ev-prov-1"],
        proof_refs=["P-prov"],
    )
    proof = VulnerabilityProof(
        proof_id="P-prov",
        finding_id="F-prov",
        mission_id="mis-prov",
        target_id="tgt-prov",
        evidence_ids=["ev-prov-1"],
        proof_status="proven",
    )

    exec_repo.save(execution)
    obs_repo.save(observation)
    ev_repo.save(evidence)
    finding_repo.save(finding)
    proof_repo.save(proof)

    # Reload everything and verify the chain is intact.
    obs = obs_repo.get(observation.id)
    ev = ev_repo.get(evidence.id)
    f = finding_repo.get(finding.id)
    p = proof_repo.get(proof.id)
    ex = exec_repo.get(execution.id)

    assert obs is not None and obs.evidence_ref == "ev-prov-1"
    assert obs.target_id == "tgt-prov" and obs.mission_id == "mis-prov"
    assert ev is not None and ev.evidence_id == "ev-prov-1"
    assert ev.raw_artifact_ref == "artifacts/mis-prov/nuclei/out.json"
    assert f is not None and f.evidence_refs == ["ev-prov-1"]
    assert f.proof_refs == ["P-prov"]
    assert p is not None and p.evidence_ids == ["ev-prov-1"]
    assert p.finding_id == "F-prov"
    assert ex is not None and ex.tool_id == "nuclei"


def test_which_tool_produced_which_observation(backend_factory) -> None:
    """Observations from different tools stay separately attributable."""
    repo = backend_factory.repository_for(ObservationRecord)
    repo.save_many(
        [
            ObservationRecord(observation_id=f"obs-{tool}", target_id="tgt-1", mission_id="mis-1", tool=tool, value="80/tcp open")
            for tool in ("nmap", "naabu", "masscan")
        ]
    )
    by_tool = {
        obs.tool: obs.observation_id
        for obs in repo.stream()
        if obs.target_id == "tgt-1" and obs.value == "80/tcp open"
    }
    assert by_tool == {"nmap": "obs-nmap", "naabu": "obs-naabu", "masscan": "obs-masscan"}
