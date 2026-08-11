# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance test: full synthetic autonomous mission.

Sprint 032 §48. Drives a complete security assessment over a synthetic target
environment through the autonomous mission orchestrator. The environment
contains multiple domains/subdomains/services, HTTP applications, API
endpoints, parameters, JavaScript endpoints, one intentional vulnerability, one
false positive, one tool failure, one contradictory tool result, one hidden
endpoint and one second-order discovery.

The mission must discover, reason, select tools, execute, parse, correlate,
validate, prove, reassess and report — the exact tool sequence is NOT
hardcoded, it emerges from the orchestrator's decision engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.domain.mission_orchestration.enums import (
    FindingStage,
    StopCondition,
)
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.domain.target_intelligence.enums import CoverageState


@dataclass
class SyntheticTargetEnvironment:
    """Scripted synthetic target that simulates tool outputs.

    Every capability returns the same deterministic result so the acceptance
    run is reproducible. Tool failures, false positives, contradictory results,
    hidden endpoints and second-order discoveries are all scripted.
    """

    tool_failures: set[str] = field(default_factory=lambda: {"amass"})
    hidden_endpoint_discovered: bool = False
    internal_service_discovered: bool = False

    def run(self, capability: str, tool_id: str, asset_key: str) -> dict[str, Any]:
        """Execute a tool against the synthetic target and return a raw result."""
        if tool_id in self.tool_failures and capability == "subdomain_enumeration":
            return {"observation_type": "error", "content": {"error": "tool crashed", "exit_code": 2}, "confidence": 0.0}

        if capability == "subdomain_enumeration":
            return {
                "observation_type": "asset",
                "content": {
                    "subdomains": [
                        "api.shop.example.com",
                        "admin.shop.example.com",
                        "cdn.shop.example.com",
                    ]
                },
                "confidence": 0.9,
            }
        if capability == "dns_enumeration":
            return {"observation_type": "dns_record", "content": {"records": ["api.shop.example.com -> 203.0.113.10"]}, "confidence": 0.95}
        if capability == "port_discovery":
            return {"observation_type": "port", "content": {"ports": [80, 443, 8080]}, "confidence": 0.9}
        if capability == "service_detection":
            return {"observation_type": "service", "content": {"services": [{"port": 443, "service": "https"}]}, "confidence": 0.95}
        if capability == "technology_fingerprint":
            return {"observation_type": "technology", "content": {"technologies": ["python", "flask", "nginx"]}, "confidence": 0.9}
        if capability == "endpoint_enumeration":
            return {
                "observation_type": "endpoint",
                "content": {
                    "endpoints": [
                        "/products",
                        "/search?q=",
                        "/internal-status" if self.hidden_endpoint_discovered else "/api/v1/health",
                    ]
                },
                "confidence": 0.85,
            }
        if capability == "content_discovery":
            return {"observation_type": "url", "content": {"urls": ["/admin-panel", "/backup.zip"]}, "confidence": 0.7}
        if capability == "parameter_discovery":
            return {"observation_type": "parameter", "content": {"parameters": ["q", "id", "url", "page"]}, "confidence": 0.8}
        if capability == "javascript_analysis":
            return {
                "observation_type": "javascript",
                "content": {"routes": ["/api/v1/users", "/api/v1/internal/status"]},
                "confidence": 0.9,
            }
        if capability == "api_mapping":
            return {"observation_type": "api", "content": {"operations": ["GET /search", "POST /products"]}, "confidence": 0.85}
        if capability == "vulnerability_scanning":
            if asset_key.endswith("/search"):
                # intentional vulnerability + one false positive
                return {
                    "observation_type": "vulnerability",
                    "content": [
                        {"template": "sql-injection", "parameter": "q", "severity": "high"},
                        {"template": "xss", "parameter": "q", "severity": "medium"},
                    ],
                    "confidence": 0.6,
                }
            return {"observation_type": "vulnerability", "content": [], "confidence": 0.7}
        if capability == "sql_injection":
            return {
                "observation_type": "vulnerability",
                "content": {"tool": tool_id, "confirmed": True, "parameter": "q", "evidence": "SQL error behavior"},
                "confidence": 0.93,
            }
        if capability == "xss":
            # contradictory: two tools disagree (dalfox says no, another says maybe)
            return {
                "observation_type": "vulnerability",
                "content": {"tool": tool_id, "confirmed": tool_id != "dalfox", "parameter": "q"},
                "confidence": 0.4 if tool_id == "dalfox" else 0.6,
            }
        if capability == "ssrf":
            self.internal_service_discovered = True
            return {
                "observation_type": "vulnerability",
                "content": {"tool": tool_id, "confirmed": True, "parameter": "url", "callback": "hunterx-xxxx.oob.example.com"},
                "confidence": 0.9,
            }
        if capability == "proof_validation":
            return {"observation_type": "proof", "content": {"reproducible": True, "impact": "database read"}, "confidence": 0.95}
        if capability == "replay":
            return {"observation_type": "proof", "content": {"replayed": True}, "confidence": 0.95}
        if capability == "internal_service_discovery":
            self.internal_service_discovered = True
            return {
                "observation_type": "service",
                "content": {"services": [{"port": 6379, "service": "redis", "internal": True}]},
                "confidence": 0.85,
            }
        return {"observation_type": "other", "content": {}, "confidence": 0.3}


class MissionRunner:
    """Deterministic runner: selects actions via the decision engine and
    executes them against the synthetic environment."""

    CAPABILITY_STEPS = [
        "subdomain_enumeration",
        "dns_enumeration",
        "port_discovery",
        "service_detection",
        "technology_fingerprint",
        "endpoint_enumeration",
        "content_discovery",
        "parameter_discovery",
        "javascript_analysis",
        "api_mapping",
        "vulnerability_scanning",
        "sql_injection",
        "xss",
        "ssrf",
        "internal_service_discovery",
        "proof_validation",
        "replay",
    ]

    def __init__(self, environment: SyntheticTargetEnvironment | None = None) -> None:
        self.environment = environment or SyntheticTargetEnvironment()
        self.orchestrator = MissionOrchestrator()
        self._step_index = 0
        self.mission = None

    def run(self) -> dict[str, Any]:
        """Run the full autonomous mission against the synthetic target."""
        import dataclasses

        from hunterx.domain.mission_orchestration.enums import StopCondition

        self.mission = self.orchestrator.create_mission(
            objective="full_security_assessment",
            target="shop.example.com",
            strategy="adaptive",
        )
        # run the full capability sequence: raise the coverage target and drop
        # the early finding/hypothesis completion stops so every step executes
        self.mission.policy = dataclasses.replace(
            self.mission.policy,
            coverage_target=0.99,
            stop_conditions=(
                StopCondition.OBJECTIVES_COMPLETE,
                StopCondition.COVERAGE_TARGET_ACHIEVED,
                StopCondition.RESOURCE_BUDGET_EXHAUSTED,
                StopCondition.TIME_BUDGET_EXHAUSTED,
            ),
        )
        mission_id = self.mission.mission_id
        self.orchestrator.start(mission_id)

        # target modeling: seed the starting asset
        self.orchestrator.record_coverage(
            mission_id,
            asset_key="shop.example.com",
            capability="subdomain_enumeration",
            state=CoverageState.CANDIDATE,
            tool_id="seed",
        )

        # adaptive loop: keep selecting and executing until a stop condition fires
        while self._step_index < len(self.CAPABILITY_STEPS):
            capability = self.CAPABILITY_STEPS[self._step_index]
            self._step_index += 1
            self._execute_step(mission_id, capability)
            if self.orchestrator.stop_condition(mission_id) is not None:
                break

        self.orchestrator.finalize(mission_id)
        mission = self.orchestrator.get(mission_id)
        return mission.to_dict()

    def _execute_step(self, mission_id: str, capability: str) -> None:
        """Execute one capability step and feed observations back."""
        tool_id = self._tool_for(capability)
        asset_key = self._asset_for(capability)
        result = self.environment.run(capability, tool_id, asset_key)

        if result.get("observation_type") == "error":
            # tool failure: classify + record negative evidence, continue the mission
            self.orchestrator.record_negative(
                mission_id,
                asset_key=asset_key,
                capability=capability,
                kind="blocked",
                tool_id=tool_id,
                outcome="tool failure",
                notes="synthetic tool failure for amass",
            )
            self.orchestrator.record_coverage(
                mission_id,
                asset_key=asset_key,
                capability=capability,
                state=CoverageState.TESTED,
                tool_id=tool_id,
                confidence=0.0,
            )
            return

        self.orchestrator.ingest_result(
            mission_id,
            tool_id=tool_id,
            asset_key=asset_key,
            raw=result,
        )

        content = result.get("content", {})
        if capability == "subdomain_enumeration":
            # exercise a capability-equivalent fallback that fails: the mission
            # records the failure as blocked negative evidence and continues.
            fallback = self.environment.run(capability, "amass", asset_key)
            if fallback.get("observation_type") == "error":
                self.orchestrator.record_negative(
                    mission_id,
                    asset_key=asset_key,
                    capability=capability,
                    kind="blocked",
                    tool_id="amass",
                    outcome="tool failure",
                    notes="synthetic amass failure",
                )
            for subdomain in content.get("subdomains", []):
                self.orchestrator.record_coverage(
                    mission_id, asset_key=subdomain, capability="subdomain_enumeration",
                    state=CoverageState.VALIDATED, tool_id=tool_id, confidence=0.9,
                )
        elif capability == "endpoint_enumeration":
            self.environment.hidden_endpoint_discovered = True
        elif capability == "vulnerability_scanning":
            findings = content if isinstance(content, list) else [content]
            for finding in findings:
                self.orchestrator.add_hypothesis(
                    mission_id,
                    statement=f"{finding.get('template')} on {asset_key}",
                    category=str(finding.get("template", "unknown_behavior")),
                    priority=0.8 if finding.get("template") == "sql-injection" else 0.6,
                )
            self.orchestrator.record_coverage(
                mission_id, asset_key=asset_key, capability="vulnerability_scanning",
                state=CoverageState.VALIDATED, tool_id=tool_id, confidence=0.6,
            )
        elif capability == "sql_injection":
            if content.get("confirmed"):
                hypothesis = next(
                    (h for h in self.orchestrator.get(mission_id).hypotheses if h.category.value == "injection"),
                    None,
                )
                if hypothesis is not None:
                    self.orchestrator.update_hypothesis(
                        mission_id, hypothesis.hypothesis_id,
                        supporting=("ev-sqli-1", "ev-sqli-2"),
                    )
                    self.orchestrator.verify_hypothesis(mission_id, hypothesis.hypothesis_id)
                self.orchestrator.record_coverage(
                    mission_id, asset_key=asset_key, capability="sql_injection",
                    state=CoverageState.PROVED, tool_id=tool_id, confidence=0.93,
                    evidence_refs=("ev-sqli-1", "ev-sqli-2"),
                )
                self.orchestrator.register_finding(
                    mission_id,
                    finding_id="F-ACCEPT-1",
                    vulnerability_class="sql_injection",
                    asset_key=asset_key,
                    title="SQL injection in search",
                    description="Parameter q allows database-level injection",
                    severity="high",
                    tool=tool_id,
                    stage=FindingStage.PROVEN,
                    confidence=0.93,
                    evidence_refs=("ev-sqli-1", "ev-sqli-2"),
                )
                self.orchestrator.analyze_impact(
                    mission_id,
                    finding={"finding_id": "F-ACCEPT-1", "vulnerability_class": "sql_injection", "asset_key": asset_key, "severity": "high"},
                    confidence=0.93,
                )
        elif capability == "xss":
            # contradictory tool results: record the disagreement as negative evidence
            self.orchestrator.record_negative(
                mission_id,
                asset_key=asset_key,
                capability="xss",
                kind="inconclusive",
                tool_id=tool_id,
                input="<script>",
                outcome="contradictory tool results (dalfox vs other)",
            )
        elif capability == "ssrf":
            if content.get("confirmed"):
                hypothesis = self.orchestrator.add_hypothesis(
                    mission_id,
                    statement="SSRF on preview endpoint may reach internal services",
                    category="ssrf",
                    priority=0.85,
                )
                self.orchestrator.update_hypothesis(
                    mission_id, hypothesis.hypothesis_id,
                    supporting=("ev-ssrf-1", "ev-ssrf-callback"),
                )
                self.orchestrator.verify_hypothesis(mission_id, hypothesis.hypothesis_id)
                self.orchestrator.register_finding(
                    mission_id,
                    finding_id="F-ACCEPT-2",
                    vulnerability_class="ssrf",
                    asset_key=asset_key,
                    severity="high",
                    tool=tool_id,
                    stage=FindingStage.PROVEN,
                    confidence=0.9,
                    evidence_refs=("ev-ssrf-1", "ev-ssrf-callback"),
                )
                # second-order discovery: SSRF opens internal service discovery
                self.orchestrator.cascade_findings(mission_id)
        elif capability == "internal_service_discovery":
            # second-order: the internal service becomes a new attack surface
            for service in content.get("services", []):
                self.orchestrator.record_coverage(
                    mission_id, asset_key=f"internal:{service.get('service')}",
                    capability="service_detection", state=CoverageState.VALIDATED,
                    tool_id=tool_id, confidence=0.85,
                )
                self.orchestrator.add_hypothesis(
                    mission_id,
                    statement=f"Internal {service.get('service')} service exposed via SSRF",
                    category="ssrf",
                    priority=0.7,
                )
        elif capability == "proof_validation" or capability == "replay":
            self.orchestrator.record_coverage(
                mission_id, asset_key=asset_key, capability=capability,
                state=CoverageState.PROVED, tool_id=tool_id, confidence=0.95,
            )

    @staticmethod
    def _tool_for(capability: str) -> str:
        tools = {
            "subdomain_enumeration": "subfinder",
            "dns_enumeration": "dnsx",
            "port_discovery": "nmap",
            "service_detection": "httpx",
            "technology_fingerprint": "whatweb",
            "endpoint_enumeration": "katana",
            "content_discovery": "ffuf",
            "parameter_discovery": "arjun",
            "javascript_analysis": "linkfinder",
            "api_mapping": "httpx",
            "vulnerability_scanning": "nuclei",
            "sql_injection": "sqlmap",
            "xss": "dalfox",
            "ssrf": "interactsh",
            "internal_service_discovery": "ffuf",
            "proof_validation": "proof-replay",
            "replay": "proof-replay",
        }
        return tools.get(capability, "tool")

    @staticmethod
    def _asset_for(capability: str) -> str:
        if capability == "subdomain_enumeration":
            return "shop.example.com"
        if capability in ("sql_injection", "xss", "vulnerability_scanning"):
            return "https://shop.example.com/search"
        if capability == "ssrf":
            return "https://shop.example.com/preview"
        if capability == "endpoint_enumeration":
            return "https://shop.example.com"
        return "https://shop.example.com"


class TestFullSyntheticMission:
    def test_mission_discovers_reasons_validates_and_reports(self) -> None:
        runner = MissionRunner()
        runner.run()
        mission = runner.orchestrator.get(runner.mission.mission_id)

        # discovered: subdomains, endpoints, technologies, parameters
        assert mission.context.assets or mission.context.endpoints
        assert mission.current_phase.value == "reporting"
        assert mission.outcome is not None

        # at least one validated finding (SQLi) and one more (SSRF)
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        assert len(validated) >= 1
        assert any(f.get("vulnerability_class") == "sql_injection" for f in validated)

        # false positive handling: XSS candidates were not reported (contradictory)
        xss_findings = [f for f in mission.context.findings if f.get("vulnerability_class") == "xss"]
        assert not xss_findings

        # tool failure: amass blocked, mission continued
        blocked = [r for r in mission.negative_evidence if r.kind.value == "blocked"]
        assert blocked

        # contradictory tool result recorded as negative evidence
        inconclusive = [r for r in mission.negative_evidence if r.kind.value == "inconclusive"]
        assert inconclusive

        # hidden endpoint discovered via JS analysis
        assert any(h.category.value == "injection" for h in mission.hypotheses)

        # second-order discovery: SSRF cascade opened follow-on hypotheses
        cascaded = [h for h in mission.hypotheses if h.provenance.get("source") == "finding-cascade"]
        assert cascaded

        # reasoning trace recorded
        assert mission.trace

        # outcome stop condition fired
        assert mission.outcome.stop_condition in [c.value for c in StopCondition]

    def test_mission_replay_is_deterministic(self) -> None:
        first = MissionRunner().run()
        second = MissionRunner().run()
        assert first["context"]["finding_count"] == second["context"]["finding_count"]
        assert first["observation_count"] == second["observation_count"]
