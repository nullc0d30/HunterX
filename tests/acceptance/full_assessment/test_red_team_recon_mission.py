# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sprint 033 §19 — Red-Team Reconnaissance & Validation mission acceptance test.

Demonstrates a multi-step attack path through the FINDING A creates knowledge →
knowledge changes attack surface → attack path B becomes possible → B is tested
→ B produces evidence loop:

discovered asset (subdomain) → exposed service (port 8080) → application (admin
panel) → credential/secret (hardcoded API key in JS) → authenticated API →
authorization weakness (privileged endpoint reachable with user token) →
validated impact.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.enums import FindingStage
from hunterx.domain.target_intelligence.enums import CoverageState
from tests.acceptance.full_assessment._harness import (
    FullSpectrumMissionRunner,
    MissionScenario,
    ToolScenario,
)


def _scenario() -> MissionScenario:
    scenario = MissionScenario(
        name="red_team_recon",
        objective="red_team_assessment",
        target="victim.example.com",
        description="Red-team recon and validation across a multi-step attack path ending in an authorization weakness.",
    )

    # 1. recon — asset discovery (FINDING A: the subdomain)
    scenario.add(
        ToolScenario(
            capability="subdomain_enumeration",
            tool_id="subfinder",
            asset_key="victim.example.com",
            result={
                "observation_type": "asset",
                "content": {"subdomains": ["internal.victim.example.com"]},
                "confidence": 0.9,
            },
        )
    )

    # 2. the discovered asset changes the surface: exposed admin service
    def _service(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.record_coverage(
            mission_id,
            asset_key="internal.victim.example.com:8080",
            capability="service_detection",
            state=CoverageState.VALIDATED,
            tool_id="nmap",
            confidence=0.9,
        )

    scenario.add(
        ToolScenario(
            capability="port_discovery",
            tool_id="nmap",
            asset_key="internal.victim.example.com",
            result={"observation_type": "port", "content": {"ports": [8080]}, "confidence": 0.9},
        )
    ).add(
        ToolScenario(
            capability="service_detection",
            tool_id="httpx",
            asset_key="internal.victim.example.com",
            result={"observation_type": "service", "content": {"status": 200, "server": "jetty", "title": "Admin console"}, "confidence": 0.95},
            post=_service,
        )
    )

    # 3. credential/secret discovered in JS (knocks over to the authenticated API)
    def _secret(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.support_hypothesis(
            mission_id,
            statement="Hardcoded API key in admin console JS grants API access",
            supporting=("ev-secret-js",),
            verify=False,
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="internal.victim.example.com",
            capability="secret_detection",
            tool_id="secretfinder",
            evidence_refs=("ev-secret-js",),
        )

    scenario.add(
        ToolScenario(
            capability="secret_detection",
            tool_id="secretfinder",
            asset_key="internal.victim.example.com",
            result={
                "observation_type": "secret",
                "content": {"secrets": [{"kind": "api_key", "name": "ADMIN_API_KEY", "path": "/assets/app.js"}]},
                "confidence": 0.85,
            },
            post=_secret,
        )
    )

    # 4. authenticated API probed with the discovered key (ATTACK PATH B)
    def _auth_api(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.support_hypothesis(
            mission_id,
            statement="API key authenticates against internal API",
            supporting=("ev-auth-200",),
            verify=False,
        )

    scenario.add(
        ToolScenario(
            capability="api_mapping",
            tool_id="httpx",
            asset_key="internal.victim.example.com/api",
            result={"observation_type": "api", "content": {"operations": ["GET /api/admin/users"], "authenticated": True}, "confidence": 0.9},
            post=_auth_api,
        )
    )

    # 5. authorization weakness — privileged endpoint reachable with the user token
    def _authz(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="Authorization weakness: user token can read /api/admin/users",
            category="auth_bypass",
            priority=0.9,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-admin-200", "ev-token-role"),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="authorization_bypass",
            asset_key="internal.victim.example.com/api/admin/users",
            severity="critical",
            tool="manual-probe",
            stage=FindingStage.PROVEN,
            confidence=0.92,
            evidence_refs=("ev-admin-200", "ev-token-role"),
            title="Authorization bypass on admin API with user token",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="internal.victim.example.com/api/admin/users",
            capability="authorization_analysis",
            tool_id="manual-probe",
            evidence_refs=("ev-admin-200", "ev-token-role"),
        )

    scenario.add(
        ToolScenario(
            capability="authorization_analysis",
            tool_id="manual-probe",
            asset_key="internal.victim.example.com/api/admin/users",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "method": "GET", "role": "user", "evidence": "admin data returned with user token"},
                "confidence": 0.92,
            },
            post=_authz,
        )
    )

    # 6. reassessment cascade
    scenario.add(
        ToolScenario(
            capability="reassessment",
            tool_id="orchestrator",
            asset_key="victim.example.com",
            result={"observation_type": "other", "content": {"reassessed": True}, "confidence": 0.9},
            post=lambda runner, mission_id, step: runner.orchestrator.cascade_findings(mission_id),
        )
    )

    scenario.expected = {
        "findings_validated": 1,
        "authorization_bypass_validated": True,
        "secret_discovered": True,
        "follow_on_hypotheses": True,
    }
    return scenario


class TestRedTeamReconMission:
    def test_multi_step_attack_path(self) -> None:
        runner = FullSpectrumMissionRunner(_scenario())
        summary = runner.run()
        mission = runner.orchestrator.get(summary["mission_id"])

        # 1. the authorization bypass is validated (the end of the path)
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        assert any(f.get("vulnerability_class") == "authorization_bypass" for f in validated)

        # 2. the intermediate knowledge (subdomain, secret, auth) was retained
        observed_secrets = [o for o in mission.observations if o.observation_type == "secret"]
        assert observed_secrets
        assert any("internal.victim.example.com" in str(k) for k in mission.context.assets)

        # 3. attack path: knowledge from finding A created path B
        #    The secret observation created the authenticated-API hypothesis.
        hypotheses = mission.hypotheses
        assert any("API key" in h.statement for h in hypotheses)
        assert any("Authorization weakness" in h.statement for h in hypotheses)

        # 4. the authorization hypothesis was validated (proved the path end)
        authz_hyp = next((h for h in hypotheses if "Authorization weakness" in h.statement), None)
        assert authz_hyp is not None
        assert authz_hyp.state.value == "validated"

        # 5. reassessment opened follow-on hypotheses
        cascaded = [h for h in mission.hypotheses if h.provenance.get("source") == "finding-cascade"]
        assert cascaded

        # 6. impact assessed and mission completed
        assert mission.impact_analyses
        assert mission.outcome is not None
        assert mission.current_phase.value == "reporting"
