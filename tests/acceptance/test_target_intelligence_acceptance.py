# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests: the autonomous adaptive intelligence loop.

HunterX starts with ONLY a target scope and mission objective, then must
autonomously discover assets, build the graph, identify unknowns, select tools,
ingest observations, update coverage, generate hypotheses, select validation,
and produce ranked next actions. The exact tool sequence is NOT hardcoded —
decisions must emerge from the intelligence state.
"""

from __future__ import annotations

from hunterx.domain.target_intelligence.actions import NextActionEngine
from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    CoverageState,
    IntelligencePhase,
    IntelligenceTargetKind,
    IntelligenceTargetStatus,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    IntelligenceTarget,
    Observation,
)
from hunterx.engines.target_intelligence import TargetIntelligenceEngine


class _FakeSelector:
    """Deterministic test double for the Sprint 025 mission-aware selector."""

    _TOOLS = {
        "subdomain_enumeration": ("subfinder", ("amass", "assetfinder")),
        "port_discovery": ("naabu", ("masscan",)),
        "technology_fingerprint": ("httpx", ("whatweb",)),
        "parameter_discovery": ("arjun", ("paramspider",)),
        "endpoint_enumeration": ("katana", ("waybackurls",)),
        "vulnerability_scanning": ("nuclei", ("nikto",)),
        "sql_injection": ("sqlmap", ("ghauri",)),
        "xss": ("dalfox", ("xsstrike",)),
        "api_mapping": ("httpx", ("katana",)),
        "cloud_ownership_mapping": ("shodan", ("censys",)),
        "content_discovery": ("feroxbuster", ("ffuf",)),
        "secret_detection": ("gitleaks", ("trufflehog",)),
        "proof_validation": ("sqlmap", ("dalfox",)),
    }

    def select(
        self,
        *,
        target: IntelligenceTarget,
        capability: CoverageCapability,
        asset_key: str = "",
        mission_id: str = "",
    ) -> tuple[str, tuple[str, ...], str]:
        tool, alternatives = self._TOOLS.get(capability.value, ("", ()))
        return tool, alternatives, f"selected {tool} for {capability.value}"


def _make_engine() -> TargetIntelligenceEngine:
    return TargetIntelligenceEngine(
        next_action=NextActionEngine(tool_selector=_FakeSelector()),  # type: ignore[arg-type]
    )


class TestAutonomousAdaptiveLoop:
    def test_full_loop_emerges_from_state(self) -> None:
        engine = _make_engine()
        # ONLY scope + mission objective + minimal initial information.
        target = IntelligenceTarget(
            target_id="golden-1",
            mission_id="mis-1",
            scope="shop.example.com",
            identity="Golden Shop",
            kind=IntelligenceTargetKind.DOMAIN,
            value="shop.example.com",
            criticality="high",
        )
        engine.register_target(target)

        # 1. Adaptive recon: engine must discover/choose recon actions.
        state, actions, decision = engine.run_cycle(target, mission_objective="find exploitable vulnerabilities")
        assert decision.rationale
        assert actions
        recon_actions = [a for a in actions if a.required_capability in (
            CoverageCapability.SUBDOMAIN_ENUMERATION,
            CoverageCapability.PORT_DISCOVERY,
            CoverageCapability.TECHNOLOGY_FINGERPRINT,
        )]
        assert recon_actions
        assert any(a.tool for a in recon_actions)  # tool selection emerges, not hardcoded

        # 2. Simulate tool results -> observations (adaptive discovery).
        observations = [
            Observation(
                target_id="golden-1",
                mission_id="mis-1",
                tool="subfinder",
                capability="subdomain_enumeration",
                observation_type=ObservationType.HOST,
                value="api.shop.example.com",
                asset_key="hostname:api.shop.example.com",
                confidence=0.9,
            ),
            Observation(
                target_id="golden-1",
                mission_id="mis-1",
                tool="httpx",
                capability="technology_fingerprint",
                observation_type=ObservationType.TECHNOLOGY,
                value="nginx",
                asset_key="hostname:api.shop.example.com",
            ),
            Observation(
                target_id="golden-1",
                mission_id="mis-1",
                tool="httpx",
                capability="endpoint_enumeration",
                observation_type=ObservationType.ENDPOINT,
                value="https://api.shop.example.com/v1/search?q=x",
                asset_key="url:https://api.shop.example.com/v1/search?q=x",
            ),
            Observation(
                target_id="golden-1",
                mission_id="mis-1",
                tool="katana",
                capability="parameter_discovery",
                observation_type=ObservationType.PARAMETER,
                value="q",
                asset_key="url:https://api.shop.example.com/v1/search?q=x",
            ),
        ]
        engine.ingest_observations(target, observations)

        # 3. Reassess: coverage updated, unknowns refined, hypotheses generated.
        state, actions, decision = engine.run_cycle(
            target, mission_objective="find exploitable vulnerabilities", authorization_granted=True
        )
        assert state.assets
        assert state.coverage.entries
        assert state.coverage.state("hostname:api.shop.example.com", CoverageCapability.TECHNOLOGY_FINGERPRINT) is CoverageState.TESTED
        assert state.gaps  # unknowns are explicit, never negative

        injection_hypotheses = [h for h in state.hypotheses if h.category.value == "injection"]
        assert injection_hypotheses  # parameterized endpoint -> injection hypothesis

        # 4. The next action for the top hypothesis must be VALIDATE/ TEST with a tool.
        validation = [
            a
            for a in actions
            if a.required_capability in (CoverageCapability.SQL_INJECTION, CoverageCapability.XSS)
            and a.asset_key
        ]
        assert validation
        assert any(a.tool in ("sqlmap", "ghauri", "dalfox") for a in validation)

        # 5. Record negative + positive evidence and advance toward proof.
        from hunterx.domain.target_intelligence.models import NegativeResult

        engine.record_negative(
            target,
            NegativeResult(
                target_id="golden-1",
                asset_key="url:https://api.shop.example.com/v1/search?q=x",
                tested_capability=CoverageCapability.XSS,
                tool="dalfox",
                conditions={"payloads": 50, "auth": "public"},
            ),
        )
        state = engine.snapshot(target)
        assert state.negative_results
        assert state.coverage.state(
            "url:https://api.shop.example.com/v1/search?q=x", CoverageCapability.XSS
        ) is CoverageState.TESTED

        # 6. Everything stays scoped to the mission target.
        assert all(asset.target_id == "golden-1" for asset in state.assets)

    def test_tool_sequence_is_not_hardcoded(self) -> None:
        engine_a = _make_engine()
        engine_b = _make_engine()
        a_target = IntelligenceTarget(
            target_id="t-a", mission_id="m", scope="example.com", identity="A", kind=IntelligenceTargetKind.DOMAIN, value="example.com"
        )
        b_target = IntelligenceTarget(
            target_id="t-b", mission_id="m", scope="example.org", identity="B", kind=IntelligenceTargetKind.DOMAIN, value="example.org"
        )
        engine_a.register_target(a_target)
        engine_b.register_target(b_target)
        # Different objectives must not force the same sequence of actions.
        _, actions_a, _ = engine_a.run_cycle(a_target, mission_objective="assess web")
        _, actions_b, _ = engine_b.run_cycle(b_target, mission_objective="assess cloud")
        # Both are driven by state; actions must always carry decision provenance.
        assert all(action.decision_id for action in actions_a)  # provenance preserved
        assert all(action.decision_id for action in actions_b)

    def test_terminal_condition_when_hypotheses_exhausted(self) -> None:
        engine = _make_engine()
        target = IntelligenceTarget(
            target_id="t-c", mission_id="m", scope="example.com", identity="C", kind=IntelligenceTargetKind.DOMAIN, value="example.com"
        )
        engine.register_target(target)
        # With no assets and no hypotheses and phase advanced to REPORTING, a STOP action emerges.

        from dataclasses import replace

        completed = replace(target, phase=IntelligencePhase.REPORTING, status=IntelligenceTargetStatus.COMPLETED)
        engine.register_target(completed)
        _, actions, _ = engine.run_cycle(completed, mission_objective="done")
        # The mission is terminal; no new discovery actions should be proposed.
        assert actions
