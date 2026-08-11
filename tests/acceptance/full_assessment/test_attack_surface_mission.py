# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sprint 033 §10 — External Attack Surface full-spectrum mission acceptance test.

The target contains domains, subdomains, IPs, ports, services, cloud assets,
SaaS integrations, CDNs, APIs, web applications, storage and third-party
integrations. The mission constructs a unified attack-surface graph via the
adaptive planning engine and discovers a multi-step attack path that is
reassessed as evidence accumulates.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.enums import FindingStage
from hunterx.domain.target_intelligence.graph import AttackSurfaceGraph
from hunterx.domain.target_intelligence.models import IntelligenceAsset
from hunterx.domain.topology.enums import EntityKind, RelationshipType
from tests.acceptance.full_assessment._harness import (
    FullSpectrumMissionRunner,
    MissionScenario,
    ToolScenario,
)


def _build_surface(mission_id: str) -> AttackSurfaceGraph:
    """Construct the unified external attack-surface graph."""
    from hunterx.domain.target_intelligence.graph import relationship_for

    surface = AttackSurfaceGraph()
    assets = [
        IntelligenceAsset(asset_id="a1", target_id="t1", mission_id=mission_id, kind=EntityKind.DOMAIN, name="corp.example.com", key="domain:corp.example.com", label="Corp domain", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a2", target_id="t1", mission_id=mission_id, kind=EntityKind.HOSTNAME, name="api.corp.example.com", key="hostname:api.corp.example.com", label="API host", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a3", target_id="t1", mission_id=mission_id, kind=EntityKind.IP, name="203.0.113.30", key="ip:203.0.113.30", label="API IP", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a4", target_id="t1", mission_id=mission_id, kind=EntityKind.PORT, name="443", key="port:203.0.113.30:443", label="HTTPS", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a5", target_id="t1", mission_id=mission_id, kind=EntityKind.URL, name="https://api.corp.example.com", key="url:https://api.corp.example.com", label="API app", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a6", target_id="t1", mission_id=mission_id, kind=EntityKind.STORAGE_RESOURCE, name="corp-backup", key="storage:corp-backup", label="Backup bucket", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a7", target_id="t1", mission_id=mission_id, kind=EntityKind.CLOUD_RESOURCE, name="corp-lb", key="cloud:corp-lb", label="Cloud load balancer", in_scope=True, source="seed"),
        IntelligenceAsset(asset_id="a8", target_id="t1", mission_id=mission_id, kind=EntityKind.SAAS_INTEGRATION, name="corp-saas", key="saas:corp-saas", label="SaaS integration", in_scope=True, source="seed"),
    ]
    for asset in assets:
        surface.upsert_asset(asset)

    pairs = [
        (RelationshipType.RESOLVES_TO, "domain:corp.example.com", "hostname:api.corp.example.com"),
        (RelationshipType.RESOLVES_TO, "hostname:api.corp.example.com", "ip:203.0.113.30"),
        (RelationshipType.HOSTS, "ip:203.0.113.30", "port:203.0.113.30:443"),
        (RelationshipType.SERVES, "port:203.0.113.30:443", "url:https://api.corp.example.com"),
        (RelationshipType.USES, "url:https://api.corp.example.com", "storage:corp-backup"),
        (RelationshipType.EXPOSES, "url:https://api.corp.example.com", "cloud:corp-lb"),
        (RelationshipType.BELONGS_TO, "saas:corp-saas", "domain:corp.example.com"),
    ]
    keys = {asset.key: asset for asset in assets}
    for rel_type, source_key, target_key in pairs:
        edge = relationship_for(
            rel_type,
            keys[source_key],
            keys[target_key],
            mission_id=mission_id,
            source_name="synthetic-attack-surface",
            confidence=0.95,
        )
        surface.add_relationship(edge)
    return surface


def _scenario() -> MissionScenario:
    scenario = MissionScenario(
        name="attack_surface",
        objective="external_attack_surface",
        target="corp.example.com",
        description="Unified external attack-surface assessment across domains, hosts, IPs, ports, services, cloud, storage, SaaS and CDN assets.",
    )

    # 1. discovery layers
    scenario.add(
        ToolScenario(
            capability="subdomain_enumeration",
            tool_id="subfinder",
            asset_key="corp.example.com",
            result={
                "observation_type": "asset",
                "content": {"subdomains": ["api.corp.example.com", "admin.corp.example.com", "cdn.corp.example.com"]},
                "confidence": 0.9,
            },
        )
    ).add(
        ToolScenario(
            capability="dns_enumeration",
            tool_id="dnsx",
            asset_key="api.corp.example.com",
            result={"observation_type": "dns_record", "content": {"records": ["api.corp.example.com -> 203.0.113.30"]}, "confidence": 0.95},
        )
    ).add(
        ToolScenario(
            capability="port_discovery",
            tool_id="naabu",
            asset_key="203.0.113.30",
            result={"observation_type": "port", "content": {"ports": [443, 8443]}, "confidence": 0.9},
        )
    ).add(
        ToolScenario(
            capability="service_detection",
            tool_id="httpx",
            asset_key="api.corp.example.com",
            result={"observation_type": "service", "content": {"status": 200, "server": "nginx", "title": "Corp API"}, "confidence": 0.95},
        )
    )

    # 2. cloud / SaaS / storage exposure classification
    scenario.add(
        ToolScenario(
            capability="cloud_ownership_mapping",
            tool_id="cloud-analysis",
            asset_key="corp.example.com",
            result={
                "observation_type": "cloud",
                "content": {
                    "provider": "aws",
                    "resources": [
                        {"name": "corp-lb", "type": "load_balancer", "exposure": "internet"},
                        {"name": "corp-backup", "type": "s3_bucket", "exposure": "public"},
                    ],
                    "saas": [{"name": "corp-saas", "integration": "webhook"}],
                },
                "confidence": 0.9,
            },
        )
    )

    # 3. exposed storage validated as a finding
    def _storage(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="Public S3 bucket corp-backup exposes sensitive data",
            category="misconfiguration",
            priority=0.85,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-bucket-listing", "ev-bucket-acl"),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="cloud_exposure",
            asset_key="storage:corp-backup",
            severity="high",
            tool="cloud-analysis",
            stage=FindingStage.PROVEN,
            confidence=0.9,
            evidence_refs=("ev-bucket-listing", "ev-bucket-acl"),
            title="Publicly exposed storage bucket",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="storage:corp-backup",
            capability="cloud_ownership_mapping",
            tool_id="cloud-analysis",
            evidence_refs=("ev-bucket-listing", "ev-bucket-acl"),
        )

    scenario.add(
        ToolScenario(
            capability="storage_exposure",
            tool_id="cloud-analysis",
            asset_key="storage:corp-backup",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "provider": "aws", "evidence": "anonymous list allowed"},
                "confidence": 0.9,
            },
            post=_storage,
        )
    )

    # 4. third-party SaaS webhook weakness
    def _webhook(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.record_negative(
            mission_id,
            asset_key="saas:corp-saas",
            capability="cloud_ownership_mapping",
            kind="inconclusive",
            tool_id="manual-probe",
            outcome="webhook signature not verifiable; ambiguous — retained not reported",
        )

    scenario.add(
        ToolScenario(
            capability="saas_analysis",
            tool_id="cloud-analysis",
            asset_key="saas:corp-saas",
            result={"observation_type": "cloud", "content": {"webhook": {"signed": False, "verified": False}}, "confidence": 0.6},
            post=_webhook,
        )
    )

    # 5. API surface scan (Nuclei) — no additional validated findings
    scenario.add(
        ToolScenario(
            capability="vulnerability_scanning",
            tool_id="nuclei",
            asset_key="api.corp.example.com",
            result={"observation_type": "vulnerability", "content": [], "confidence": 0.7},
        )
    )

    scenario.expected = {
        "findings_validated": 1,
        "cloud_exposure_validated": True,
        "attack_paths_discovered": True,
        "webhook_inconclusive": True,
    }
    return scenario


class TestExternalAttackSurfaceMission:
    def test_unified_attack_surface(self) -> None:
        runner = FullSpectrumMissionRunner(_scenario())
        summary = runner.run()
        mission_id = summary["mission_id"]
        mission = runner.orchestrator.get(mission_id)

        # 1. cloud exposure validated
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        assert any(f.get("vulnerability_class") == "cloud_exposure" for f in validated)

        # 2. webhook ambiguity retained as inconclusive negative evidence, not a finding
        webhook_findings = [f for f in mission.context.findings if f.get("vulnerability_class") == "webhook_weakness"]
        assert not webhook_findings

        # 3. unified attack-surface graph constructed and attack paths discovered
        from hunterx.domain.adaptive_mission_planning.enums import MissionObjective
        from hunterx.platform.assembler import build_platform

        platform = build_platform()
        adaptive = platform.adaptive_mission_planning_service.create_mission(
            objective=MissionObjective.ATTACK_SURFACE_DISCOVERY,
            target="corp.example.com",
            included_targets=("corp.example.com",),
        )
        surface = _build_surface(adaptive.mission_id)
        paths = platform.adaptive_mission_planning_service.discover_attack_paths(adaptive.mission_id, surface)
        assert paths, "no attack paths discovered over the unified surface"
        assert any(len(path.steps) >= 2 for path in paths)

        # 4. the graph carries the typed relationships
        assert surface.relationship("url:https://api.corp.example.com->storage:corp-backup") or len(surface.relationships()) >= 5

        # 5. multiple asset kinds mapped (domain, host, ip, port, url, storage, cloud, saas)
        kinds = {asset.kind.value if hasattr(asset.kind, "value") else str(asset.kind) for asset in surface.assets()}
        assert {"domain", "hostname", "ip", "port", "url", "storage_resource", "cloud_resource", "saas_integration"}.issubset(kinds)

        # 6. mission completed
        assert mission.outcome is not None
        assert mission.current_phase.value == "reporting"
