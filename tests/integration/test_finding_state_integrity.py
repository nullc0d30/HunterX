# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 1 — finding/validation integrity repair regression tests.

Pins the semantic boundary between an Observation, a Candidate finding and a
Validated vulnerability, and the required invariant:

* an informational scanner result (WAF detection, tech/DNS/SPF/MX
  fingerprinting, robots.txt, WHOIS/RDAP, ...) stays an observation /
  intelligence — it NEVER becomes a candidate finding, let alone a validated
  vulnerability;
* a candidate finding without verification evidence NEVER becomes
  verified/validated (it stays CANDIDATE/SUPPORTED);
* a properly verified finding (supported differential probe on a real
  vulnerability class) MAY become validated;
* repeated identical observations from the same tool, target and endpoint
  never create duplicate findings.

These tests exercise the real mission execution path (planning → decision →
execution → observation ingestion → hypothesis loop → promotion) with a
deterministic fake tool layer.
"""

from __future__ import annotations

import dataclasses

import pytest

from hunterx.application.mission_dashboard import MissionDashboardService
from hunterx.application.mission_execution import MissionExecutionService
from hunterx.application.mission_orchestration import MissionOrchestrationService
from hunterx.domain.adaptive_mission_planning.toolchain import ToolSelectionEngine
from hunterx.domain.mission_orchestration.enums import StopCondition
from hunterx.domain.mission_orchestration.orchestrator import MissionOrchestrator
from hunterx.engines.adaptive_mission_planning.engine import AdaptiveMissionPlanningEngine
from hunterx.engines.mission_orchestration import MissionOrchestrationEngine
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from tests.framework.fakes import FakeExecutionEngine
from tests.framework.vulnerable_app import VulnerableApp

#: Informational Nuclei templates that must never become vulnerabilities.
_INFORMATIONAL_TEMPLATES = (
    "dns-waf-detect",
    "waf-detect",
    "tech-detect",
    "spf-record-detect",
    "mx-fingerprint",
    "robots-txt",
    "rdap-whois",
)

_CANDIDATES: dict[str, tuple[str, ...]] = {
    "technology_fingerprint": ("whatweb",),
    "vulnerability_scanning": ("nuclei",),
    "dependency_check": ("osv-scanner",),
}


@pytest.fixture(scope="module")
def app() -> VulnerableApp:
    with VulnerableApp() as server:
        yield server


def _orchestration() -> MissionOrchestrationService:
    return MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=MissionOrchestrator()),
        stores=InMemoryTidbRepositoryFactory(),
    )


def _runner(fake: FakeExecutionEngine, *, target: str, objective: str = "vulnerability_discovery"):
    planning = AdaptiveMissionPlanningEngine(
        tool_selection_engine=ToolSelectionEngine(
            mission_type="bug-bounty",
            default_candidates=dict(_CANDIDATES),
        ),
    )
    orchestrator = MissionOrchestrator(planning=planning)
    orchestration = MissionOrchestrationService(
        engine=MissionOrchestrationEngine(orchestrator=orchestrator),
        stores=InMemoryTidbRepositoryFactory(),
    )
    runner = MissionExecutionService(
        orchestration=orchestration,
        planning=planning,
        execution_engine=fake,
    )
    mission = orchestration.create_mission(objective=objective, target=target)
    mission.policy = dataclasses.replace(
        mission.policy,
        coverage_target=0.99,
        stop_conditions=(StopCondition.COVERAGE_TARGET_ACHIEVED, StopCondition.RESOURCE_BUDGET_EXHAUSTED),
    )
    orchestration.start(mission.mission_id)
    return runner, orchestration, mission.mission_id


def _informational_findings(target: str) -> list[dict[str, object]]:
    return [
        {"template_id": template, "template_name": template, "severity": "info", "matched_at": target}
        for template in _INFORMATIONAL_TEMPLATES
    ]


class TestSemanticBoundary:
    def test_informational_templates_are_not_vulnerability_classes(self) -> None:
        from hunterx.domain.vulnerability_capability.registry import is_vulnerability_class

        for template in _INFORMATIONAL_TEMPLATES:
            assert not is_vulnerability_class(template), template
        for cls in (
            "sql-injection",
            "xss",
            "ssrf",
            "ssti",
            "lfi",
            "open-redirect",
            "security-misconfiguration",
            "swagger-api",
            "known-vulnerable-component",
        ):
            assert is_vulnerability_class(cls), cls

    def test_informational_nuclei_results_stay_observations(self) -> None:
        """Acceptance A: informational results -> observation, never a finding."""
        orchestration = _orchestration()
        target = "https://example.com"
        mission = orchestration.create_mission(objective="vulnerability_discovery", target=target)
        orchestration.start(mission.mission_id)

        orchestration.ingest_result(
            mission.mission_id,
            tool_id="nuclei",
            asset_key=target,
            raw={
                "observation_type": "vulnerability",
                "content": {"findings": _informational_findings(target)},
                "confidence": 0.5,
            },
        )
        mission = orchestration.get(mission.mission_id)

        # The scanner observation itself is retained as intelligence.
        assert mission.observations
        assert any(o.tool_id == "nuclei" for o in mission.observations)
        # No candidate finding is created for any informational template.
        assert mission.context.findings == []
        # No vulnerability hypothesis is created for them either.
        class_hypotheses = [
            h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class")
        ]
        assert class_hypotheses == []
        # The mission dashboard counts zero validated findings.
        overview = MissionDashboardService(service=orchestration).overview(mission.mission_id)
        assert overview["counts"]["validated_findings"] == 0
        assert overview["counts"]["findings"] == 0

    def test_informational_results_never_validate_end_to_end(self, app: VulnerableApp) -> None:
        """Acceptance A: even on a probe-able loopback target, no validation."""
        target = app.base_url
        fake = FakeExecutionEngine(
            outputs={
                "nuclei": {"findings": _informational_findings(target), "count": len(_INFORMATIONAL_TEMPLATES)},
                "whatweb": {"name": "python", "technologies": ["Python"]},
            }
        )
        runner, orchestration, mission_id = _runner(fake, target=target)

        runner.run(mission_id, max_cycles=12)
        mission = orchestration.get(mission_id)

        verified = [f for f in mission.context.findings if f.get("stage") == "verified"]
        validated = [h for h in mission.hypotheses if h.state.value == "validated"]
        assert verified == []
        assert validated == []
        assert not any(
            (h.provenance or {}).get("vulnerability_class") for h in mission.hypotheses
        )


class TestEvidenceGate:
    def test_candidate_without_verification_evidence_never_validates(self) -> None:
        """Acceptance B: no evidence -> finding stays CANDIDATE/SUPPORTED."""
        target = "https://example.com"
        payload = {
            "candidates": [
                {
                    "vulnerability_class": "sql-injection",
                    "endpoint": f"{target}/vuln/search",
                    "parameter": "q",
                    "severity": "medium",
                }
            ],
            "count": 1,
        }
        fake = FakeExecutionEngine(outputs={"nuclei": payload})
        runner, orchestration, mission_id = _runner(fake, target=target)

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        # A real-class candidate IS created (the boundary lets it through).
        candidate = next(
            (f for f in mission.context.findings if f.get("vulnerability_class") == "sql-injection"),
            None,
        )
        assert candidate is not None
        # The non-loopback target cannot produce a differential probe, so the
        # hypothesis never has verification evidence and no finding is promoted.
        assert not [f for f in mission.context.findings if f.get("stage") == "verified"]
        vulnerability = next(
            (h for h in mission.hypotheses if (h.provenance or {}).get("vulnerability_class") == "sql-injection"),
            None,
        )
        assert vulnerability is not None
        assert vulnerability.state.value in ("proposed", "weakly_supported", "supported")
        assert vulnerability.state.value != "validated"
        overview = MissionDashboardService(service=orchestration).overview(mission_id)
        assert overview["counts"]["validated_findings"] == 0

    def test_properly_verified_finding_can_become_validated(self, app: VulnerableApp) -> None:
        """Acceptance C: supported differential probe -> finding may validate."""
        target = app.base_url
        payload = {
            "candidates": [
                {
                    "vulnerability_class": "sql-injection",
                    "endpoint": f"{target}/vuln/search",
                    "parameter": "q",
                    "severity": "medium",
                }
            ],
            "count": 1,
        }
        fake = FakeExecutionEngine(outputs={"nuclei": payload})
        runner, orchestration, mission_id = _runner(fake, target=target)

        runner.run(mission_id, max_cycles=16)
        mission = orchestration.get(mission_id)

        verified = [f for f in mission.context.findings if f.get("stage") == "verified"]
        assert verified, "a probe-verified hypothesis must promote its finding"
        assert verified[0].get("vulnerability_class") == "sql-injection"
        assert any(h.state.value == "validated" for h in mission.hypotheses)


class TestDeduplication:
    def test_repeated_identical_observations_create_single_finding(self) -> None:
        """Acceptance D: repeated observations never multiply candidate findings."""
        orchestration = _orchestration()
        target = "https://example.com"
        mission = orchestration.create_mission(objective="vulnerability_discovery", target=target)
        orchestration.start(mission.mission_id)
        raw = {
            "observation_type": "vulnerability",
            "content": {
                "candidates": [
                    {
                        "vulnerability_class": "sql-injection",
                        "endpoint": f"{target}/vuln/search",
                        "parameter": "q",
                        "severity": "medium",
                    }
                ],
                "count": 1,
            },
            "confidence": 0.5,
        }
        for _ in range(5):
            orchestration.ingest_result(mission.mission_id, tool_id="nuclei", asset_key=target, raw=dict(raw))

        mission = orchestration.get(mission.mission_id)
        matches = [
            f
            for f in mission.context.findings
            if f.get("vulnerability_class") == "sql-injection"
        ]
        assert len(matches) == 1
        assert matches[0].get("stage") == "candidate"
        assert len(matches[0].get("evidence_refs") or []) >= 2

    def test_repeated_observations_never_create_duplicate_validated_findings(
        self, app: VulnerableApp
    ) -> None:
        """Acceptance D: a validated class+endpoint stays a single finding."""
        target = app.base_url
        payload = {
            "candidates": [
                {
                    "vulnerability_class": "sql-injection",
                    "endpoint": f"{target}/vuln/search",
                    "parameter": "q",
                    "severity": "medium",
                }
            ],
            "count": 1,
        }
        fake = FakeExecutionEngine(outputs={"nuclei": payload})
        runner, orchestration, mission_id = _runner(fake, target=target)

        runner.run(mission_id, max_cycles=24)
        mission = orchestration.get(mission_id)

        verified = [
            f for f in mission.context.findings if f.get("stage") == "verified"
        ]
        sql = [f for f in verified if f.get("vulnerability_class") == "sql-injection"]
        assert len(sql) == 1, "repeated identical observations must not duplicate the validated finding"
        assert all(f.get("finding_id") == sql[0].get("finding_id") for f in sql)
