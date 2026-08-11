# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sprint 033 §11 — Cloud/SaaS full-spectrum mission acceptance test.

Validates provider detection, resource discovery, exposure classification,
cloud relationships, SaaS discovery, webhook relationships, attack-surface
correlation and finding persistence, reusing the Sprint 017 cloud intelligence
capability. A provider misconfiguration and an insecure SaaS webhook are
validated; a fake "compromised key" secret is rejected as a false positive.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.enums import FindingStage
from tests.acceptance.full_assessment._harness import (
    FullSpectrumMissionRunner,
    MissionScenario,
    ToolScenario,
)


def _scenario() -> MissionScenario:
    scenario = MissionScenario(
        name="cloud_saas",
        objective="cloud_assessment",
        target="acme-org",
        description="Cloud/SaaS assessment: provider detection, exposure classification, cloud relationships and webhook weaknesses.",
    )

    # 1. provider detection & resource discovery
    scenario.add(
        ToolScenario(
            capability="cloud_ownership_mapping",
            tool_id="cloud-analysis",
            asset_key="acme-org",
            result={
                "observation_type": "cloud",
                "content": {
                    "provider": "azure",
                    "account": "acme-prod",
                    "resources": [
                        {"name": "acme-app", "type": "app_service", "exposure": "internet"},
                        {"name": "acme-storage", "type": "blob_container", "exposure": "public"},
                        {"name": "acme-func", "type": "function_app", "exposure": "private"},
                    ],
                },
                "confidence": 0.92,
            },
        )
    )

    # 2. SaaS discovery with webhook relationships
    scenario.add(
        ToolScenario(
            capability="saas_analysis",
            tool_id="cloud-analysis",
            asset_key="acme-org",
            result={
                "observation_type": "cloud",
                "content": {
                    "saas": [
                        {"name": "acme-jira", "integration": "webhook", "webhook_url": "https://acme-app.azurewebsites.net/hooks/jira"},
                        {"name": "acme-slack", "integration": "webhook", "webhook_url": "https://acme-app.azurewebsites.net/hooks/slack"},
                    ]
                },
                "confidence": 0.9,
            },
        )
    )

    # 3. public blob container exposure (validated)
    def _blob(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="Public blob container acme-storage exposes customer data",
            category="misconfiguration",
            priority=0.88,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-blob-1", "ev-blob-2"),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="cloud_exposure",
            asset_key="storage:acme-storage",
            severity="high",
            tool="cloud-analysis",
            stage=FindingStage.PROVEN,
            confidence=0.9,
            evidence_refs=("ev-blob-1", "ev-blob-2"),
            title="Publicly exposed Azure blob container",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="storage:acme-storage",
            capability="cloud_ownership_mapping",
            tool_id="cloud-analysis",
            evidence_refs=("ev-blob-1", "ev-blob-2"),
        )

    scenario.add(
        ToolScenario(
            capability="storage_exposure",
            tool_id="cloud-analysis",
            asset_key="storage:acme-storage",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "provider": "azure", "evidence": "anonymous container listing"},
                "confidence": 0.9,
            },
            post=_blob,
        )
    )

    # 4. insecure SaaS webhook (validated)
    def _webhook(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="Insecure webhook on acme-app accepts unsigned deliveries",
            category="misconfiguration",
            priority=0.82,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-webhook-unsigned",),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="webhook_weakness",
            asset_key="saas:acme-jira",
            severity="medium",
            tool="cloud-analysis",
            stage=FindingStage.PROVEN,
            confidence=0.85,
            evidence_refs=("ev-webhook-unsigned",),
            title="Unsigned webhook delivery accepted",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="saas:acme-jira",
            capability="saas_analysis",
            tool_id="cloud-analysis",
            evidence_refs=("ev-webhook-unsigned",),
        )

    scenario.add(
        ToolScenario(
            capability="saas_analysis",
            tool_id="cloud-analysis",
            asset_key="saas:acme-jira",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "webhook": {"signature_required": False}},
                "confidence": 0.85,
            },
            post=_webhook,
        )
    )

    # 5. fake secret rejected — "compromised key" is a decoy
    def _fake_secret(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.record_negative(
            mission_id,
            asset_key="storage:acme-storage",
            capability="secret_detection",
            kind="not_vulnerable",
            tool_id="trufflehog",
            outcome="fake secret decoy; not a live credential",
        )

    scenario.add(
        ToolScenario(
            capability="secret_detection",
            tool_id="trufflehog",
            asset_key="storage:acme-storage",
            result={"observation_type": "secret", "content": {"secrets": [{"kind": "fake_key", "live": False}]}, "confidence": 0.4},
            post=_fake_secret,
        )
    )

    # 6. reassessment cascade after cloud exposure finding
    scenario.add(
        ToolScenario(
            capability="reassessment",
            tool_id="orchestrator",
            asset_key="acme-org",
            result={"observation_type": "other", "content": {"reassessed": True}, "confidence": 0.9},
            post=lambda runner, mission_id, step: runner.orchestrator.cascade_findings(mission_id),
        )
    )

    scenario.expected = {
        "findings_validated": 2,
        "blob_exposure_validated": True,
        "webhook_validated": True,
        "fake_secret_rejected": True,
    }
    return scenario


class TestCloudSaaSMission:
    def test_cloud_saas_assessment(self) -> None:
        runner = FullSpectrumMissionRunner(_scenario())
        summary = runner.run()
        mission = runner.orchestrator.get(summary["mission_id"])

        # 1. both validated findings present
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        classes = {f.get("vulnerability_class") for f in validated}
        assert "cloud_exposure" in classes
        assert "webhook_weakness" in classes

        # 2. fake secret rejected — no secret finding promoted
        secrets = [f for f in mission.context.findings if f.get("vulnerability_class") == "secret_exposure"]
        assert not secrets

        # 3. provider detected and recorded
        providers = [
            o.content.get("provider")
            for o in mission.observations
            if o.observation_type == "cloud" and o.content.get("provider")
        ]
        assert "azure" in providers

        # 4. cloud relationships (SaaS → webhook) mapped
        saas_observations = [o for o in mission.observations if o.observation_type == "cloud"]
        assert saas_observations
        assert any("acme-jira" in str(o.content) for o in saas_observations)

        # 5. negative evidence retained for the fake secret
        negatives = [r for r in mission.negative_evidence if r.capability == "secret_detection"]
        assert any("fake secret" in str(r.outcome) for r in negatives)

        # 6. impact assessed and mission completed
        assert mission.impact_analyses
        assert mission.outcome is not None
        assert mission.current_phase.value == "reporting"
