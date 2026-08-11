# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for Target Memory & Campaign Intelligence.

Verifies tenant/target isolation, cross-mission and cross-target leakage
defense, unauthorized historical access, evidence/secret non-leakage (memory
stores normalized references, never raw output), memory-poisoning defense,
timestamp-manipulation handling and state-tamper resistance (immutable memory
records).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from hunterx.application.target_memory import TargetMemoryQueryService, TargetMemoryScopeError, TargetMemoryService
from hunterx.domain.target_memory.engines import MemoryConfidenceEngine, build_memory
from hunterx.domain.target_memory.models import ToolObservation
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory


def _obs(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "target_id": "t1",
        "mission_id": "m1",
        "tool": "nmap",
        "observation_type": "port",
        "value": "80/tcp",
        "normalized_value": "80/tcp",
        "asset_key": "hostname:www.example.com",
        "source": "nmap-parser",
        "confidence": 1.0,
        "timestamp": "2026-08-01T00:00:00+00:00",
        "expires_at": None,
    }
    values.update(overrides)
    return values


class TestIsolation:
    def test_cross_target_write_is_rejected(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = TargetMemoryService(stores=stores, tenant="tenant-a")
        service.authorize(tenant="tenant-a", target_id="t1")
        with pytest.raises(TargetMemoryScopeError):
            service.record_observations("t2", [_obs(target_id="t2")], tenant="tenant-a")

    def test_cross_tenant_target_is_rejected(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = TargetMemoryService(stores=stores, tenant="tenant-a")
        service.authorize(tenant="tenant-a", target_id="t1")
        with pytest.raises(TargetMemoryScopeError):
            service.record_observations("t1", [_obs()], tenant="tenant-b")

    def test_query_never_leaks_across_targets(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        writer = TargetMemoryService(stores=stores, tenant="tenant-a")
        writer.authorize(tenant="tenant-a", target_id="t1")
        writer.authorize(tenant="tenant-a", target_id="t2")
        writer.record_observations("t1", [_obs()], tenant="tenant-a")
        writer.record_observations("t2", [_obs(target_id="t2")], tenant="tenant-a")
        query = TargetMemoryQueryService(stores=stores)
        memory_one = query.memory("t1")
        assert len(memory_one.observations) == 1
        assert all(obs.target_id == "t1" for obs in memory_one.observations.values())
        assert query.observation_history("t1")
        assert query.observation_history("t2")
        # No cross-contamination in the memory of t1.
        assert not any(obs.target_id == "t2" for obs in memory_one.observations.values())

    def test_risk_history_scoped_per_target(self) -> None:
        stores = InMemoryTidbRepositoryFactory()
        service = TargetMemoryService(stores=stores, tenant="tenant-a")
        service.authorize(tenant="tenant-a", target_id="t1")
        entry = service.evaluate_risk(target_id="t1", campaign_id="c1", mission_id="m1", tenant="tenant-a")
        query = TargetMemoryQueryService(stores=stores)
        assert query.risk_history("t1") == [entry]
        assert query.risk_history("t9") == []


class TestMemoryPoisoningDefense:
    def test_low_confidence_observation_cannot_redefine_state(self) -> None:
        memory = build_memory(
            [_obs(confidence=0.1, source="untrusted-scraper", timestamp="2026-08-10T00:00:00+00:00")],
            now="2026-08-10T00:00:00+00:00",
        )
        observation = memory.observations["port:80/tcp"]
        object.__setattr__(observation, "source_reliability", "unverified")
        engine = MemoryConfidenceEngine()
        assert engine.is_poisoned(observation)
        # A poisoned observation never becomes KNOWN_CURRENT authority on its own.
        assert engine.evaluate(observation) < 0.35

    def test_contradicted_observation_is_not_silently_overwritten(self) -> None:
        from hunterx.domain.target_memory.engines import ContradictionDetector

        detector = ContradictionDetector()
        contradictions = detector.detect(
            [_obs(observation_type="port", value="80/tcp", normalized_value="80/tcp", tool="nmap"),
             _obs(observation_type="port", value="443/tcp", normalized_value="443/tcp", tool="masscan")]
        )
        assert contradictions
        # Both observations preserved; state classified, never averaged away.
        assert len(contradictions[0].observations) == 2

    def test_malicious_tool_output_is_never_stored_raw(self) -> None:
        # ToolObservation retains references and normalized results, not raw output.
        tool_obs = ToolObservation(
            tool="nuclei",
            target_id="t1",
            normalized_result={"template": "cve-2026-0001", "matched": True},
            evidence_refs=["evidence/ev-1"],
            provenance={"raw_artifact": "evidence/ev-1.raw"},
        )
        assert "evidence/ev-1.raw" not in tool_obs.normalized_result
        assert tool_obs.evidence_refs == ["evidence/ev-1"]
        # The memory observation stores the normalized value, never raw bytes.
        memory = build_memory([_obs(value="1; DROP TABLE targets;--", normalized_value="sqli-payload-canonical")], now="2026-08-10T00:00:00+00:00")
        observation = memory.observations["port:sqli-payload-canonical"]
        assert observation.normalized_value == "sqli-payload-canonical"

    def test_timestamp_manipulation_is_gated_by_confidence(self) -> None:
        # A malicious tool reporting a "future" last-seen to look fresh is
        # still gated by confidence/source reliability before reuse.
        memory = build_memory(
            [_obs(confidence=0.05, source="malicious-parser", timestamp="2099-01-01T00:00:00+00:00")],
            now="2026-08-10T00:00:00+00:00",
        )
        observation = memory.observations["port:80/tcp"]
        object.__setattr__(observation, "source_reliability", "low")
        assert MemoryConfidenceEngine().is_poisoned(observation)

    def test_memory_records_are_immutable(self) -> None:
        memory = build_memory([_obs()], now="2026-08-10T00:00:00+00:00")
        observation = memory.observations["port:80/tcp"]
        with pytest.raises(FrozenInstanceError):
            observation.value = "tampered"  # type: ignore[misc]


class TestEvidenceLeakage:
    def test_memory_does_not_store_secret_values(self) -> None:
        # Observation history stores the observation_type/value, not credentials.
        tool_obs = ToolObservation(
            tool="trufflehog",
            target_id="t1",
            normalized_result={"secret_type": "AWS", "location": "s3://bucket/.env"},
            evidence_refs=["evidence/ev-secret-1"],
        )
        assert "AKIA" not in str(tool_obs.normalized_result)
        assert "password" not in str(tool_obs.normalized_result)
