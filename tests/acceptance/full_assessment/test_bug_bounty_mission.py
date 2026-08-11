# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sprint 033 §7 — Bug Bounty full-spectrum mission acceptance test.

Runs a complete synthetic bug-bounty hunt against an authorized web target:
recon → enumeration → technology detection → URL discovery → parameter
discovery → JS analysis → vulnerability discovery → validation → PoC → replay →
impact assessment → report readiness. The environment contains an intentional
SQLi (validated and proven), an XSS false positive (rejected), a tool failure
(amass) that the mission recovers from, and a second-order endpoint discovered
through JS analysis.
"""

from __future__ import annotations

from hunterx.domain.mission_orchestration.baseline import TestResponse
from hunterx.domain.mission_orchestration.enums import FindingStage
from hunterx.domain.target_intelligence.enums import CoverageState
from tests.acceptance.full_assessment._harness import (
    FullSpectrumMissionRunner,
    MissionScenario,
    ToolScenario,
)


def _scenario() -> MissionScenario:
    scenario = MissionScenario(
        name="bug_bounty",
        objective="bug_bounty_hunt",
        target="shop.example.com",
        description="Synthetic bug-bounty hunt with an intentional SQLi, an XSS false positive and a tool failure.",
    )

    # 1. Recon — subdomain discovery (subfinder OK, amass fails, assetfinder corroborates)
    scenario.add(
        ToolScenario(
            capability="subdomain_enumeration",
            tool_id="subfinder",
            asset_key="shop.example.com",
            result={
                "observation_type": "asset",
                "content": {"subdomains": ["api.shop.example.com", "admin.shop.example.com", "cdn.shop.example.com"]},
                "confidence": 0.9,
            },
        )
    ).add(
        ToolScenario(
            capability="subdomain_enumeration",
            tool_id="amass",
            asset_key="shop.example.com",
            failure={"error": "tool crashed (exit 2)", "exit_code": 2},
        )
    ).add(
        ToolScenario(
            capability="subdomain_enumeration",
            tool_id="assetfinder",
            asset_key="shop.example.com",
            result={
                "observation_type": "asset",
                "content": {"subdomains": ["api.shop.example.com", "admin.shop.example.com"]},
                "confidence": 0.8,
            },
        )
    )

    # 2. Enumeration — DNS, ports, services
    scenario.add(
        ToolScenario(
            capability="dns_enumeration",
            tool_id="dnsx",
            asset_key="api.shop.example.com",
            result={"observation_type": "dns_record", "content": {"records": ["api.shop.example.com -> 203.0.113.10"]}, "confidence": 0.95},
        )
    ).add(
        ToolScenario(
            capability="port_discovery",
            tool_id="nmap",
            asset_key="api.shop.example.com",
            result={"observation_type": "port", "content": {"ports": [80, 443, 8080]}, "confidence": 0.9},
        )
    ).add(
        ToolScenario(
            capability="service_detection",
            tool_id="httpx",
            asset_key="api.shop.example.com",
            result={"observation_type": "service", "content": {"status": 200, "server": "nginx", "title": "Shop API"}, "confidence": 0.95},
        )
    )

    # 3. Understand — technology fingerprinting
    scenario.add(
        ToolScenario(
            capability="technology_fingerprint",
            tool_id="whatweb",
            asset_key="api.shop.example.com",
            result={"observation_type": "technology", "content": {"technologies": ["python", "flask", "nginx"]}, "confidence": 0.9},
        )
    )

    # 4. Map — URL discovery (katana + GAU corroboration)
    scenario.add(
        ToolScenario(
            capability="endpoint_enumeration",
            tool_id="katana",
            asset_key="api.shop.example.com",
            result={
                "observation_type": "endpoint",
                "content": {"endpoints": ["/search?q=", "/internal-status", "/v1/users?id=", "/preview?url="]},
                "confidence": 0.9,
            },
        )
    ).add(
        ToolScenario(
            capability="endpoint_enumeration",
            tool_id="gau",
            asset_key="api.shop.example.com",
            result={
                "observation_type": "url",
                "content": {"urls": ["/search?q=", "/preview?url="]},
                "confidence": 0.8,
            },
        )
    )

    # 5. Parameter discovery
    scenario.add(
        ToolScenario(
            capability="parameter_discovery",
            tool_id="arjun",
            asset_key="api.shop.example.com/search",
            result={"observation_type": "parameter", "content": {"parameters": ["q", "page"]}, "confidence": 0.8},
        )
    )

    # 6. JS analysis — reveals a hidden second-order endpoint
    def _js_analysis(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.record_coverage(
            mission_id,
            asset_key="https://api.shop.example.com/internal-status",
            capability="endpoint_enumeration",
            state=CoverageState.VALIDATED,
            tool_id="linkfinder",
            confidence=0.8,
        )

    scenario.add(
        ToolScenario(
            capability="javascript_analysis",
            tool_id="linkfinder",
            asset_key="api.shop.example.com",
            result={
                "observation_type": "javascript",
                "content": {"routes": ["/api/v1/users", "/api/v1/internal/status"]},
                "confidence": 0.9,
            },
            post=_js_analysis,
        )
    )

    # 7. Vulnerability discovery — intentional SQLi + XSS false positive
    def _vuln_scan(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="SQLi on /search?q may allow database access",
            category="injection",
            priority=0.9,
        )
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="XSS reflection on /search?q",
            category="xss",
            priority=0.4,
        )

    scenario.add(
        ToolScenario(
            capability="vulnerability_scanning",
            tool_id="nuclei",
            asset_key="api.shop.example.com/search",
            result={
                "observation_type": "vulnerability",
                "content": [
                    {"template": "sql-injection", "parameter": "q", "severity": "high"},
                    {"template": "xss", "parameter": "q", "severity": "medium"},
                ],
                "confidence": 0.6,
            },
            post=_vuln_scan,
        )
    )

    # 8. Validation — SQLi confirmed via differential + independent tool
    def _sqli_validation(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.capture_baseline(
            mission_id,
            asset_key="api.shop.example.com/search",
            request_fingerprint="GET /search?q=1",
            status_code=200,
            content_length=200,
            headers={"server": "nginx"},
        )
        runner.orchestrator.differential_test(
            mission_id,
            asset_key="api.shop.example.com/search",
            classification_hint="sql_injection",
            test=TestResponse(
                status_code=500,
                content_length=400,
                body="SQL syntax error near hunterxprobe",
            ),
        )
        hypothesis = next(
            (h for h in runner.orchestrator.get(mission_id).hypotheses if h.category.value == "injection"),
            None,
        )
        if hypothesis is not None:
            runner.orchestrator.update_hypothesis(
                mission_id, hypothesis.hypothesis_id, supporting=("ev-sqli-1", "ev-sqli-diff")
            )
            runner.orchestrator.verify_hypothesis(mission_id, hypothesis.hypothesis_id)
        runner.record_proof_coverage(
            mission_id,
            asset_key="api.shop.example.com/search",
            capability="sql_injection",
            tool_id="sqlmap",
            evidence_refs=("ev-sqli-1", "ev-sqli-diff"),
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="sql_injection",
            asset_key="api.shop.example.com/search",
            severity="high",
            tool="sqlmap",
            stage=FindingStage.PROVEN,
            confidence=0.93,
            evidence_refs=("ev-sqli-1", "ev-sqli-diff"),
            title="SQL injection in the search parameter",
        )

    scenario.add(
        ToolScenario(
            capability="sql_injection",
            tool_id="sqlmap",
            asset_key="api.shop.example.com/search",
            result={
                "observation_type": "vulnerability",
                "content": {"tool": "sqlmap", "confirmed": True, "parameter": "q", "evidence": "SQL error behavior"},
                "confidence": 0.93,
            },
            post=_sqli_validation,
        )
    )

    # 9. False positive rejection — XSS is not exploitable (contradictory tools)
    def _xss_fp(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.record_negative(
            mission_id,
            asset_key="api.shop.example.com/search",
            capability="xss",
            kind="not_vulnerable",
            tool_id="dalfox",
            outcome="payload reflected but not executed; no XSS",
        )

    scenario.add(
        ToolScenario(
            capability="xss",
            tool_id="dalfox",
            asset_key="api.shop.example.com/search",
            result={"observation_type": "vulnerability", "content": {"confirmed": False, "parameter": "q"}, "confidence": 0.2},
            post=_xss_fp,
        )
    )

    # 10. Reassessment cascade after the validated SQLi finding
    scenario.add(
        ToolScenario(
            capability="reassessment",
            tool_id="orchestrator",
            asset_key="api.shop.example.com",
            result={"observation_type": "other", "content": {"reassessed": True}, "confidence": 0.9},
            post=lambda runner, mission_id, step: runner.orchestrator.cascade_findings(mission_id),
        )
    )

    scenario.expected = {
        "findings_validated": 1,
        "vuln_class": "sql_injection",
        "xss_not_reported": True,
        "tool_failure_recovered": True,
        "hidden_endpoint_discovered": True,
        "follow_on_hypotheses": True,
    }
    return scenario


class TestBugBountyMission:
    def test_full_bug_bounty_hunt(self) -> None:
        runner = FullSpectrumMissionRunner(_scenario())
        summary = runner.run()
        mission = runner.orchestrator.get(summary["mission_id"])

        # 1. validated SQLi finding, report-ready stage
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        assert any(f.get("vulnerability_class") == "sql_injection" for f in validated)

        # 2. XSS false positive rejected — never promoted
        xss = [f for f in mission.context.findings if f.get("vulnerability_class") == "xss"]
        assert not xss

        # 3. tool failure (amass) recovered — blocked negative evidence recorded
        blocked = [r for r in mission.negative_evidence if r.kind.value == "blocked"]
        assert any(r.tool_id == "amass" for r in blocked)

        # 4. subdomain corroboration across subfinder + assetfinder (multi-tool consensus)
        observed_subdomains = {
            str(item)
            for obs in mission.observations
            for item in obs.content.get("subdomains", [])
            if obs.tool_id in ("subfinder", "assetfinder")
        }
        assert "api.shop.example.com" in observed_subdomains

        # 5. hidden endpoint discovered via JS analysis
        assert any("internal-status" in str(e) for e in mission.context.endpoints)

        # 6. reassessment cascade opened follow-on hypotheses
        cascaded = [h for h in mission.hypotheses if h.provenance.get("source") == "finding-cascade"]
        assert cascaded

        # 7. impact assessed for the validated finding
        assert mission.impact_analyses

        # 8. mission finalized with an outcome
        assert mission.outcome is not None
        assert mission.current_phase.value == "reporting"
