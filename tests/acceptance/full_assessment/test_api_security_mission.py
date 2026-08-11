# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Sprint 033 §9 — API Security full-spectrum mission acceptance test.

Synthetic REST/GraphQL environment. The mission discovers API endpoints,
methods, parameters, schemas, authentication, hidden endpoints, GraphQL
operations and introspection. Tools correlated include Kiterunner (hidden
endpoints), Arjun (parameters), Katana (routes), InQL/GraphQLmap (GraphQL),
HTTPx (probe) and Nuclei (scan). Validates a GraphQL introspection exposure and
a BOLA (broken object-level authorization), while a schema-exposure claim from
a single tool is rejected.
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
        name="api_security",
        objective="api_assessment",
        target="https://api.example.com",
        description="Synthetic REST/GraphQL API security assessment with introspection and BOLA findings.",
    )

    # 1. API mapping — REST surface
    scenario.add(
        ToolScenario(
            capability="api_mapping",
            tool_id="httpx",
            asset_key="api.example.com",
            result={
                "observation_type": "api",
                "content": {"operations": ["GET /v1/users/{id}", "POST /v1/orders", "GET /v1/products"]},
                "confidence": 0.9,
            },
        )
    )

    # 2. hidden endpoint discovery (Kiterunner)
    def _kiterunner(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.record_coverage(
            mission_id,
            asset_key="https://api.example.com/admin/users",
            capability="endpoint_enumeration",
            state=CoverageState.VALIDATED,
            tool_id="kiterunner",
            confidence=0.8,
        )

    scenario.add(
        ToolScenario(
            capability="endpoint_enumeration",
            tool_id="kiterunner",
            asset_key="api.example.com",
            result={
                "observation_type": "endpoint",
                "content": {"endpoints": ["/admin/users", "/internal/health", "/v1/export"]},
                "confidence": 0.8,
            },
            post=_kiterunner,
        )
    )

    # 3. parameter discovery across Arjun + Katana (corroborated)
    scenario.add(
        ToolScenario(
            capability="parameter_discovery",
            tool_id="arjun",
            asset_key="api.example.com/v1/users",
            result={"observation_type": "parameter", "content": {"parameters": ["id", "include"]}, "confidence": 0.85},
        )
    ).add(
        ToolScenario(
            capability="endpoint_enumeration",
            tool_id="katana",
            asset_key="api.example.com/v1/users",
            result={"observation_type": "endpoint", "content": {"endpoints": ["/v1/users?id=", "/v1/orders?userId="]}, "confidence": 0.85},
        )
    )

    # 4. GraphQL discovery — schema present + introspection enabled
    scenario.add(
        ToolScenario(
            capability="graphql_enumeration",
            tool_id="inql",
            asset_key="api.example.com/graphql",
            result={
                "observation_type": "graphql",
                "content": {"schema": True, "operations": ["query { user(id:) }", "query { order(id:) }"], "introspection": True},
                "confidence": 0.9,
            },
        )
    )

    # 5. GraphQL introspection exposure (validated)
    def _introspection(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="GraphQL introspection is enabled and exposes the full schema",
            category="misconfiguration",
            priority=0.85,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-graphql-introspect", "ev-graphql-types"),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="graphql_introspection",
            asset_key="api.example.com/graphql",
            severity="medium",
            tool="graphqlmap",
            stage=FindingStage.PROVEN,
            confidence=0.88,
            evidence_refs=("ev-graphql-introspect", "ev-graphql-types"),
            title="GraphQL introspection exposure",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="api.example.com/graphql",
            capability="graphql_security",
            tool_id="graphqlmap",
            evidence_refs=("ev-graphql-introspect", "ev-graphql-types"),
        )

    scenario.add(
        ToolScenario(
            capability="graphql_security",
            tool_id="graphqlmap",
            asset_key="api.example.com/graphql",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "introspection": True, "evidence": "schema dump returned"},
                "confidence": 0.88,
            },
            post=_introspection,
        )
    )

    # 6. BOLA — object-level authorization failure on /v1/orders/{id}
    def _bola(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.orchestrator.add_hypothesis(
            mission_id,
            statement="BOLA: /v1/orders/{id} returns another tenant's order without authorization",
            category="idor",
            priority=0.9,
        )
        runner.orchestrator.update_hypothesis(
            mission_id,
            runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id,
            supporting=("ev-bola-1", "ev-bola-2"),
        )
        runner.orchestrator.verify_hypothesis(
            mission_id, runner.orchestrator.get(mission_id).hypotheses[-1].hypothesis_id
        )
        runner.register_finding(
            mission_id,
            vulnerability_class="bola",
            asset_key="api.example.com/v1/orders/42",
            severity="high",
            tool="nuclei",
            stage=FindingStage.PROVEN,
            confidence=0.91,
            evidence_refs=("ev-bola-1", "ev-bola-2"),
            title="Broken object-level authorization on orders",
        )
        runner.record_proof_coverage(
            mission_id,
            asset_key="api.example.com/v1/orders/42",
            capability="api_security",
            tool_id="nuclei",
            evidence_refs=("ev-bola-1", "ev-bola-2"),
        )

    scenario.add(
        ToolScenario(
            capability="api_security",
            tool_id="nuclei",
            asset_key="api.example.com/v1/orders/42",
            result={
                "observation_type": "vulnerability",
                "content": {"confirmed": True, "method": "GET", "evidence": "cross-tenant order returned"},
                "confidence": 0.91,
            },
            post=_bola,
        )
    )

    # 7. schema exposure claim from a single tool — false positive
    def _schema_fp(runner: FullSpectrumMissionRunner, mission_id: str, step: ToolScenario) -> None:
        runner.record_negative(
            mission_id,
            asset_key="api.example.com/v1/export",
            capability="api_security",
            kind="not_vulnerable",
            tool_id="manual-probe",
            outcome="schema endpoint not reachable; single-tool claim not corroborated",
        )

    scenario.add(
        ToolScenario(
            capability="api_security",
            tool_id="manual-probe",
            asset_key="api.example.com/v1/export",
            result={"observation_type": "vulnerability", "content": {"confirmed": False}, "confidence": 0.3},
            post=_schema_fp,
        )
    )

    # 8. reassessment cascade
    scenario.add(
        ToolScenario(
            capability="reassessment",
            tool_id="orchestrator",
            asset_key="api.example.com",
            result={"observation_type": "other", "content": {"reassessed": True}, "confidence": 0.9},
            post=lambda runner, mission_id, step: runner.orchestrator.cascade_findings(mission_id),
        )
    )

    scenario.expected = {
        "findings_validated": 2,
        "introspection_validated": True,
        "bola_validated": True,
        "schema_not_reported": True,
        "hidden_endpoint_discovered": True,
    }
    return scenario


class TestApiSecurityMission:
    def test_full_api_security_assessment(self) -> None:
        runner = FullSpectrumMissionRunner(_scenario())
        summary = runner.run()
        mission = runner.orchestrator.get(summary["mission_id"])

        # 1. both validated findings present
        validated = [f for f in mission.context.findings if f.get("stage") in ("proven", "report_ready", "verified")]
        classes = {f.get("vulnerability_class") for f in validated}
        assert "graphql_introspection" in classes
        assert "bola" in classes

        # 2. single-tool schema claim rejected
        schema = [f for f in mission.context.findings if f.get("vulnerability_class") == "schema_exposure"]
        assert not schema

        # 3. hidden admin endpoint discovered via Kiterunner
        assert any("admin" in str(e) for e in mission.context.endpoints)

        # 4. negative evidence preserved for the rejected claim
        negatives = [r for r in mission.negative_evidence if r.capability == "api_security"]
        assert any("not corroborated" in str(r.outcome) for r in negatives)

        # 5. GraphQL object relationships mapped (schema operations ingested)
        graphql_observations = [o for o in mission.observations if o.observation_type in ("graphql", "api")]
        assert graphql_observations

        # 6. impact assessed and mission completed
        assert mission.impact_analyses
        assert mission.outcome is not None
        assert mission.current_phase.value == "reporting"
