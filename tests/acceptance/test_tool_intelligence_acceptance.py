# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the Sprint 023 Tool Intelligence Layer.

End-to-end scenario through the layer: register tools with full Sprint 023
knowledge (safety, scope, resources, evidence mappings, proof capabilities),
plan a dependency-aware chain, enforce every pre-execution gate, select with a
safety ceiling, escalate within scope, run a reference adapter, correlate the
canonical observations, record target intelligence and verify deterministic
state — all without executing any external binary.
"""

from __future__ import annotations

from dataclasses import replace

from hunterx.domain.exceptions import ToolSelectionError
from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    ChainStatus,
    EscalationLevel,
    EvidenceStrength,
    ToolAvailabilityStatus,
    ToolConfidenceCeiling,
    ToolEvidenceMapping,
    ToolInputField,
    ToolInputSchema,
    ToolInvocationContract,
    ToolProofCapability,
    ToolRateLimitProfile,
    ToolResourceRequirements,
    ToolSafetyClass,
    ToolSafetyProfile,
    ToolScopeProfile,
    ToolSelectionCriteria,
)
from hunterx.tools.intelligence.adapters import PortScannerAdapter
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.intelligence.enforcement import EnforcementViolation
from tests.framework.tip import make_compatibility, make_knowledge, make_metadata


def _register_web_stack(tip: ToolIntelligenceAPI) -> None:
    """Register a web-recon stack with full Sprint 023 knowledge."""
    tip.register_tool(
        make_metadata(
            "crawler",
            category="recon",
            subcategory="http",
            description="Crawl a web app for endpoints.",
        ),
        knowledge=replace(
            make_knowledge(
                "crawler",
                capabilities=("web-crawling",),
                accepts=("url",),
                required_inputs=("url",),
            ),
            input_schema=ToolInputSchema(
                fields=(ToolInputField(name="url", kind="url", required=True, scope_linked=True),),
                required=("url",),
                target_type="url",
                timeout=30.0,
            ),
            invocation_contract=ToolInvocationContract(
                command="katana",
                arguments=(ToolInputField(name="url", kind="url", required=True),),
                network_policy="allowed",
                filesystem_policy="scoped",
                scope_policy="inherit",
                expected_exit_codes=(0,),
                timeout=30.0,
            ),
            safety_profile=ToolSafetyProfile(safety_class=ToolSafetyClass.PASSIVE),
            scope_profile=ToolScopeProfile(follows_redirects=True, redirect_scope="inherit"),
            resource_requirements=ToolResourceRequirements(
                cpu_estimate=0.2,
                memory_estimate_mb=128.0,
                disk_estimate_mb=20.0,
                timeout=30.0,
                concurrency_class="light",
                rate_limit=ToolRateLimitProfile(requests_per_second=5.0, concurrency=1),
            ),
        ),
        compatibility=make_compatibility("crawler"),
    )

    tip.register_tool(
        make_metadata(
            "scanner",
            category="recon",
            subcategory="network",
            description="Scan a host for open ports.",
        ),
        knowledge=replace(
            make_knowledge(
                "scanner",
                capabilities=("port-scanning",),
                accepts=("host", "ip"),
                required_inputs=("host",),
            ),
            input_schema=ToolInputSchema(
                fields=(ToolInputField(name="host", kind="host", required=True, scope_linked=True),),
                required=("host",),
                target_type="host",
            ),
            invocation_contract=ToolInvocationContract(
                command="nmap",
                arguments=(ToolInputField(name="host", kind="host", required=True),),
                network_policy="allowed",
                scope_policy="inherit",
                timeout=60.0,
            ),
            safety_profile=ToolSafetyProfile(
                safety_class=ToolSafetyClass.LOW_IMPACT_ACTIVE
            ),
            scope_profile=ToolScopeProfile(),
            resource_requirements=ToolResourceRequirements(
                cpu_estimate=0.5,
                memory_estimate_mb=256.0,
                timeout=60.0,
                rate_limit=ToolRateLimitProfile(requests_per_second=3.0, concurrency=1),
            ),
        ),
        compatibility=make_compatibility("scanner"),
    )

    tip.register_evidence_mapping(
        ToolEvidenceMapping(
            tool_id="scanner",
            observation_kind="port",
            evidence_type="port-open",
            strength=EvidenceStrength.DETECTION,
            vulnerability_classes=("misconfiguration",),
        )
    )
    tip.register_confidence_ceiling(
        ToolConfidenceCeiling(
            tool_id="scanner", detection_ceiling=0.6, proof_ceiling=0.6
        )
    )
    tip.register_proof_capability(
        ToolProofCapability(
            tool_id="scanner",
            vulnerability_class="misconfiguration",
            proof_strategy_id="port-open",
            supported_proof_types=("replay",),
            replay_support=True,
        )
    )


class TestToolIntelligenceAcceptance:
    def test_end_to_end_layer_flow(self) -> None:
        tip = ToolIntelligenceAPI()
        _register_web_stack(tip)
        for tool_id in ("crawler", "scanner"):
            tip.install(tool_id)
            tip.verify(tool_id)
            tip.make_available(tool_id)

        # 1. Selection respects the safety ceiling.
        selections = tip.select_intelligence(
            ToolSelectionCriteria(
                required_capabilities=("port-scanning",),
                target_type="host",
                require_installed=True,
            ),
            authorization=ToolSafetyClass.ACTIVE,
        )
        assert selections
        assert selections[0].tool_id == "scanner"
        assert selections[0].confidence_ceiling <= 0.6
        assert selections[0].expected_proof_capability is True

        # 2. Planning produces a dependency-aware chain.
        chain = tip.plan_chain(
            "enumerate-web-host",
            capabilities=("web-crawling", "port-scanning"),
            authorization=ToolSafetyClass.ACTIVE,
            inputs={"url": "https://app.example.com/"},
        )
        assert len(chain.steps) == 2
        assert chain.dependencies

        # 3. Enforcement validates, scopes and protects against injection.
        validated = tip.enforce_execution(
            "scanner",
            authorization=ToolSafetyClass.ACTIVE,
            values={"host": "app.example.com"},
            target="app.example.com",
            authorized_scope=("app.example.com",),
        )
        assert validated == {"host": "app.example.com"}

        try:
            tip.enforce_execution(
                "scanner",
                authorization=ToolSafetyClass.ACTIVE,
                values={"host": "app.example.com; rm -rf /"},
                target="app.example.com",
                authorized_scope=("app.example.com",),
            )
            raise AssertionError("shell metacharacters were not blocked")
        except EnforcementViolation:
            pass

        # 4. Escalation stays inside scope and authorization.
        decision = tip.escalate(
            tool_id="scanner",
            level=EscalationLevel.ACTIVE_VALIDATION,
            capability="port-scanning",
            authorization=ToolSafetyClass.ACTIVE,
            scope_ok=True,
            evidence=("obs-1",),
        )
        assert decision.allowed is True

        out_of_scope = tip.escalate(
            tool_id="scanner",
            level=EscalationLevel.PROOF,
            capability="port-scanning",
            authorization=ToolSafetyClass.ACTIVE,
            scope_ok=False,
        )
        assert out_of_scope.allowed is False

        # 5. Reference adapter produces canonical observations.
        adapter = PortScannerAdapter()
        result = adapter.run(target="app.example.com", metadata={"tool_id": "scanner", "tool_version": "1.0.0", "target_id": "app.example.com"})
        assert result.observations
        assert all(isinstance(o, CanonicalObservation) for o in result.observations)

        # 6. Correlation respects the confidence ceiling.
        chains = tip.correlate(list(result.observations))
        assert chains
        assert all(chain.confidence <= 0.6 for chain in chains)

        # 7. Target intelligence records the execution.
        tip.record_execution(
            tool_id="scanner",
            target="app.example.com",
            observations=result.observations,
            duration_ms=900,
        )
        snapshot = tip.target_snapshot("app.example.com")
        assert snapshot.execution_history
        assert snapshot.known_evidence
        assert "scanner" in snapshot.tool_coverage
        assert tip.layer.targets.has_executed("app.example.com", "scanner") is True

        # 8. Availability and reliability tracking.
        tip.report_availability("scanner", ToolAvailabilityStatus.INSTALLED, reason="ok")
        assert tip.layer.reliability.available("scanner") is True
        stats = tip.reliability("scanner")
        assert stats.successful_executions >= 1

        # 9. A chain estimate is deterministic.
        estimated = tip.layer.estimate(chain)
        assert estimated.status is ChainStatus.PLANNED
        assert len(estimated.step_results) == 2

    def test_selection_never_picks_above_ceiling(self) -> None:
        tip = ToolIntelligenceAPI()
        _register_web_stack(tip)
        tip.install("scanner")
        tip.verify("scanner")
        tip.make_available("scanner")

        try:
            tip.select_intelligence(
                ToolSelectionCriteria(
                    required_capabilities=("port-scanning",),
                    require_installed=True,
                ),
                authorization=ToolSafetyClass.PASSIVE,
            )
            raise AssertionError("scanner (low-impact-active) selected under passive ceiling")
        except ToolSelectionError:
            pass
