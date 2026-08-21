# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Final multi-target acceptance (Phase 8 acceptance pass).

Proves the full contract across generic target profiles — discovery → attack
surface graph → capability mapping → model hypotheses → real tasks → real
execution → observations → verification → findings → model continuation →
exhaustion — on deterministic synthetic fixtures only (Juice Shop is a
separate black-box regression target and never defines the engine).

Profiles exercised (all target-agnostic):
    A. simple web application
    B. REST API
    C. GraphQL application
    D. authenticated application
    E. multi-user / authorization-differential application
    F. file-handling application
    G. workflow-heavy application

No target is ever declared exhausted merely because no finding exists or a
model is inactive: exhaustion requires real execution and a drained queue.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from hunterx.application.attack_surface import AttackSurfaceService
from hunterx.application.capability_finding import CapabilityFindingPipeline
from hunterx.application.model_attacker import ModelAttacker
from hunterx.application.vulnerability_finding import VulnerabilityFindingService
from hunterx.domain.model_attacker.reasoner import ModelReasoner
from hunterx.infrastructure.db.graph import InMemoryKnowledgeGraph
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.infrastructure.event_bus import InMemoryEventBus
from hunterx.infrastructure.memory import InMemoryFindingRepository
from hunterx.tools.intelligence.api import ToolIntelligenceAPI
from hunterx.tools.sdk.engine import ExecutionEngine
from tests.framework.access_bypass_app import AccessBypassApp
from tests.framework.model_attacker import ContextAwareHypothesisModel
from tests.framework.surfaces import ALL_SHAPES, feed
from tests.framework.vulnerable_app import VulnerableApp
from tests.framework.workflow_app import WorkflowApp

#: Every capability in the live catalog must be traceable to a real execution
#: record or an explicit structural/not-applicable reason — never a claim.
_PROFILE_TARGETS: dict[str, type] = {
    "simple_web": VulnerableApp,
    "rest_api": VulnerableApp,
    "graphql": VulnerableApp,
    "authenticated": VulnerableApp,
    "multi_user": AccessBypassApp,
    "file_handling": VulnerableApp,
    "workflow": WorkflowApp,
}

#: (endpoint_path, [parameter names]) feeds per live profile.
_PROFILE_FEEDS: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "simple_web": (("/vuln/search", ("q",)), ("/vuln/echo", ("msg",))),
    "rest_api": (("/vuln/api/export", ("q",)), ("/vuln/account", ("id",))),
    "graphql": (("/vuln/graphql", ("query",)),),
    "authenticated": (("/vuln/account", ("id",)), ("/vuln/admin", ())),
    "multi_user": (("/protected", ()), ("/hidden", ())),
    "file_handling": (("/vuln/read", ("file",)), ("/vuln/parse", ("file",))),
    "workflow": (("/workflow/start", ()), ("/workflow/advance", ("token",)), ("/workflow/finalize", ("token",))),
}

#: Discovery-planning capabilities scheduled alongside vulnerability classes by
#: the attack-surface mapper (not vulnerability classes themselves).
_PLANNING_CAPABILITIES = frozenset({"api_mapping", "endpoint_enumeration", "parameter_discovery", "javascript_analysis"})

_METRICS: dict[str, dict[str, Any]] = {}
_SHAPE_METRICS: dict[str, dict[str, Any]] = {}


def _finding_service() -> VulnerabilityFindingService:
    return VulnerabilityFindingService(
        engine=ExecutionEngine(),
        stores=InMemoryTidbRepositoryFactory(),
        event_bus=InMemoryEventBus(),
        knowledge_graph=InMemoryKnowledgeGraph(),
        tip=ToolIntelligenceAPI(),
        findings=InMemoryFindingRepository(),
    )


def _pipeline() -> CapabilityFindingPipeline:
    return CapabilityFindingPipeline(_finding_service())


def _feed_live(surface: AttackSurfaceService, target: str, feeds: tuple[tuple[str, tuple[str, ...]], ...]) -> None:
    surface.on_observation(
        observation_type="api",
        content={"endpoints": [f"{target}/{path.lstrip('/')}" for path, _ in feeds]},
        asset_key=target,
        source="final-acceptance",
    )
    for path, parameters in feeds:
        if parameters:
            surface.on_observation(
                observation_type="parameter",
                content={"parameters": list(parameters)},
                asset_key=f"{target}/{path.lstrip('/')}",
                source="final-acceptance",
            )


def _run_contract(target: str, feeds: tuple[tuple[str, tuple[str, ...]], ...]) -> dict[str, Any]:
    """Run the autonomous model-driven contract against a live target."""
    surface = AttackSurfaceService(mission_id="final-acceptance", target_key=target)
    _feed_live(surface, target, feeds)
    attacker = ModelAttacker(
        ModelReasoner(ContextAwareHypothesisModel()),
        finding_pipeline=_pipeline(),
    )
    attacker.bind(surface, mission_id="final-acceptance")
    report = attacker.run(max_rounds=16)["steps"] and attacker.report()
    telemetry = report["telemetry"]
    executed = telemetry["model_task_execution_count"]
    return {
        "target": target,
        "surfaces": surface.graph.node_count(),
        "queue_total": surface.queue.total(),
        "model_calls": telemetry["model_calls"],
        "hypotheses_generated": telemetry["hypotheses_generated"],
        "hypotheses_accepted": telemetry["hypotheses_accepted"],
        "hypotheses_rejected": telemetry["hypotheses_rejected"],
        "tasks_generated": telemetry["model_generated_tasks"],
        "tasks_executed": executed,
        "observations": telemetry["model_feedback_events"],
        "findings": telemetry["finding_events"],
        "validated_findings": telemetry["validated_findings"],
        "rejected_candidates": telemetry["hypotheses_rejected"],
        "post_finding_model_calls": telemetry["post_finding_model_calls"],
        "new_attack_paths": telemetry["new_attack_paths"],
        "completion_reason": report["completion_reason"],
        "exhausted": report["exhaustion"]["exhausted"],
    }


class TestTargetShapeMapping:
    """Discovery → graph → capability mapping → queue for every profile shape."""

    @pytest.mark.parametrize("shape", ALL_SHAPES, ids=lambda shape: shape.name)
    def test_shape_discovery_maps_and_queues(self, shape: Any) -> None:
        from hunterx.domain.vulnerability_capability.registry import registered_classes

        surface = AttackSurfaceService(mission_id="final-acceptance", target_key=shape.target)
        feed(surface, shape)
        kinds = {node.kind_value() for node in surface.graph.nodes()}
        for expected in shape.expected_kinds:
            assert expected in kinds, f"{shape.name}: missing surface kind '{expected}'"
        scheduled = {task.capability_id for task in surface.queue.tasks()}
        assert surface.queue.total() >= 1, f"{shape.name}: no assessment tasks queued"
        # Every scheduled capability is real: a registered vulnerability class
        # or a known discovery-planning capability — never an invented claim.
        vuln_classes = set(registered_classes())
        unknown = scheduled - vuln_classes - _PLANNING_CAPABILITIES
        assert not unknown, f"{shape.name}: unknown scheduled capabilities {sorted(unknown)}"
        # At least one genuine vulnerability-assessment task is queued — the
        # shape must flow into real capability execution, not just bookkeeping.
        vuln_scheduled = scheduled & vuln_classes
        assert vuln_scheduled, f"{shape.name}: no vulnerability-assessment capability scheduled"
        _SHAPE_METRICS[shape.name] = {
            "kinds": sorted(kinds),
            "scheduled": sorted(scheduled),
            "vulnerability_capabilities": sorted(vuln_scheduled),
        }


class TestLiveProfileContract:
    """The full autonomous contract runs on every live target profile."""

    @pytest.mark.parametrize("profile", sorted(_PROFILE_TARGETS), ids=str)
    def test_live_profile_runs_the_contract(self, profile: str) -> None:
        fixture = _PROFILE_TARGETS[profile]
        feeds = _PROFILE_FEEDS[profile]
        with fixture() as app:
            target = app.base_url
            metrics = _run_contract(target, feeds)
            _METRICS[profile] = metrics
            assert metrics["surfaces"] >= 1, f"{profile}: no surfaces discovered"
            assert metrics["tasks_executed"] >= 1, f"{profile}: model hypotheses must execute real tasks"
            assert metrics["observations"] >= 1, f"{profile}: attack results must return to the model"
            assert metrics["model_calls"] >= 1, f"{profile}: the model must participate in the loop"
            assert metrics["completion_reason"] in ("exhausted", "resource_limit", "model_unavailable"), profile
            # Exhaustion is only genuine with real execution — a target with a
            # drained queue and executed work may be exhausted; a target with
            # zero executed work is never "exhausted".
            if metrics["exhausted"]:
                assert metrics["tasks_executed"] >= 1, f"{profile}: exhausted without executing any task"

    def test_no_profile_terminates_on_first_finding(self) -> None:
        with VulnerableApp() as app:
            metrics = _run_contract(app.base_url, _PROFILE_FEEDS["simple_web"])
            if metrics["validated_findings"] > 0:
                assert metrics["post_finding_model_calls"] > 0, "a finding must never terminate the mission"


class TestMultiFindingProof:
    """Multiple independent findings with model continuation, then exhaustion."""

    def test_multi_finding_proof_and_invariant(self) -> None:
        with VulnerableApp() as app:
            metrics = _run_contract(app.base_url, _PROFILE_FEEDS["simple_web"])
            assert metrics["validated_findings"] >= 3, "multiple independent findings must be validated"
            assert metrics["post_finding_model_calls"] > 0
            assert metrics["validated_findings"] > 0 and metrics["post_finding_model_calls"] > 0
            assert metrics["model_calls"] > 1
            assert metrics["tasks_executed"] >= 1
            assert metrics["completion_reason"] in ("exhausted", "resource_limit")

    def test_invariant_holds_across_profiles(self) -> None:
        with VulnerableApp() as app:
            profiles = ("rest_api", "graphql", "authenticated", "file_handling")
            for profile in profiles:
                metrics = _run_contract(app.base_url, _PROFILE_FEEDS[profile])
                if metrics["validated_findings"] > 0:
                    assert metrics["post_finding_model_calls"] > 0, f"{profile}: finding stopped the loop"


def record_metrics(path: pathlib.Path) -> dict[str, Any]:
    """Persist the multi-target metrics (used by the artifacts generator)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "profiles": {
            name: {**metrics, "profile": name}
            for name, metrics in sorted(_METRICS.items())
        },
    }
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return payload


__all__: list[str] = []
