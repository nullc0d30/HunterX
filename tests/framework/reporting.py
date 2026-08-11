# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Test doubles for the professional reporting capability.

Builds findings in an in-memory TIDB store and constructs a fully wired
:class:`ProfessionalReportingService` for golden, acceptance, security and
performance tests.
"""

from __future__ import annotations

from typing import Any

from hunterx.application.professional_reporting import ProfessionalReportingService
from hunterx.domain.entities.tidb.finding_orchestration import (
    FindingImpactAssessment,
    FindingPoC,
    FindingRecord,
    FindingReplayRecord,
    FindingRootCause,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.reporting.exporter import ReportExporter
from hunterx.shared.ids import generate_id


def build_service(
    *,
    exporter: bool = True,
) -> tuple[ProfessionalReportingService, InMemoryTidbRepositoryFactory]:
    """Build a reporting service over a fresh in-memory TIDB store."""
    stores = InMemoryTidbRepositoryFactory()
    service = ProfessionalReportingService(
        stores=stores,
        event_bus=InMemoryEventBus(),
        exporter=ReportExporter() if exporter else None,
    )
    return service, stores


def create_finding(
    stores: InMemoryTidbRepositoryFactory,
    scenario: dict[str, Any],
    *,
    finding_id: str | None = None,
    mission_id: str = "mission-1",
    target_id: str = "https://app.example.com/login",
) -> str:
    """Persist a finding described by a reporting scenario.

    Args:
        stores: the in-memory TIDB store.
        scenario: reporting scenario mapping.
        finding_id: explicit finding id (random when omitted).
        mission_id: owning mission.
        target_id: canonical target.

    Returns:
        The finding identifier.

    """
    fid = finding_id or generate_id()
    observations = [
        {
            "evidence_id": generate_id(),
            "kind": item.get("kind", "detection_signature"),
            "value": item.get("value", ""),
            "quality": item.get("quality", "medium"),
            "source": item.get("source", "validation"),
            "tool_id": item.get("tool_id", "scanner"),
            "confidence": item.get("confidence", 0.8),
        }
        for item in scenario.get("evidence", [])
    ]
    scope: dict[str, object] = {"scope_ok": scenario.get("scope_ok", True)}
    if "asset_importance" in scenario:
        scope["asset_importance"] = scenario["asset_importance"]
    if "internet_exposure" in scenario:
        scope["internet_exposure"] = scenario["internet_exposure"]
    if scenario.get("on_attack_path"):
        scope["on_attack_path"] = True
    if scenario.get("attack_path_validated"):
        scope["attack_path_validated"] = True

    stores.repository_for(FindingRecord).save(
        FindingRecord(
            id=fid,
            finding_id=fid,
            mission_id=mission_id,
            target_id=target_id,
            vulnerability_class=scenario["vulnerability_class"],
            title=f"{scenario['vulnerability_class']} finding",
            description=f"description for {scenario['vulnerability_class']}",
            severity="high",
            confidence=scenario.get("confidence", 0.5),
            status=scenario.get("finding_state", "validated"),
            asset_id="asset-1",
            affected_assets=["asset-1"],
            affected_endpoints=["/login"],
            affected_parameters=["id"],
            observations=observations,
            evidence_refs=[item["evidence_id"] for item in observations],
            validation_refs=["validation-1"],
            proof_refs=["poc-1"],
            scope=scope,
            provenance="nuclei",
        )
    )

    impact = scenario.get("impact", {})
    stores.repository_for(FindingImpactAssessment).save(
        FindingImpactAssessment(
            assessment_id=generate_id(),
            finding_id=fid,
            dimensions={str(key): str(value) for key, value in impact.items()},
            evidence_refs={str(key): [item["evidence_id"] for item in observations] for key in impact},
            reasoning=["impact assessed from evidence"],
            assessed_at="2026-01-01T00:00:00Z",
        )
    )

    if scenario.get("proof_validated"):
        stores.repository_for(FindingPoC).save(
            FindingPoC(
                id=generate_id(),
                poc_id="poc-1",
                finding_id=fid,
                format="http_request",
                content="GET /login?id=1 OR 1=1",
                lifecycle_state="proof_validated",
                content_hash="abc123",
                redacted=True,
            )
        )

    for index in range(scenario.get("replays_confirmed", 0)):
        stores.repository_for(FindingReplayRecord).save(
            FindingReplayRecord(
                replay_id=generate_id(),
                poc_id="poc-1",
                finding_id=fid,
                target=target_id,
                scope_verified=True,
                hypothesis_verified=True,
                input_hash="inp",
                behavior="vulnerable",
                evidence_class=scenario["vulnerability_class"],
                verdict="confirmed",
                replayed_at=f"2026-01-0{index + 1}T00:00:00Z",
            )
        )
    for _ in range(max(0, scenario.get("replay_attempts", 0) - scenario.get("replays_confirmed", 0))):
        stores.repository_for(FindingReplayRecord).save(
            FindingReplayRecord(
                replay_id=generate_id(),
                poc_id="poc-1",
                finding_id=fid,
                target=target_id,
                verdict="not_reproducible",
                replayed_at="2026-01-09T00:00:00Z",
            )
        )

    if scenario.get("root_cause"):
        stores.repository_for(FindingRootCause).save(
            FindingRootCause(
                root_cause_id=generate_id(),
                mission_id=mission_id,
                related_finding_ids=[fid],
                affected_assets=["asset-1"],
                description=scenario["root_cause"],
                evidence_ids=[item["evidence_id"] for item in observations],
            )
        )
    return fid


def load_scenarios() -> list[dict[str, Any]]:
    """Load the reporting golden scenarios from the JSON fixture."""
    import json
    from pathlib import Path

    path = Path(__file__).parent.parent / "golden" / "reporting" / "scenarios.json"
    with path.open(encoding="utf-8") as handle:
        return list(json.load(handle)["scenarios"])
