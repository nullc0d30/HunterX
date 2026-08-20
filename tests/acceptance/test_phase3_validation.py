# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 3 — universal end-to-end assessment validation.

Final validation phase. Proves the target-agnostic pipeline end to end:

    1. generic pipeline operation over nine abstract target models (no
       target-specific knowledge),
    2. a real black-box regression against ``http://localhost:3010`` treated as
       an arbitrary external target (discovered by HunterX, never preconfigured),
    3. the generic pipeline metrics, capability-coverage matrix, adaptive
       control behavior, finding quality, and the exhaustion completion gate.

Juice Shop is only a regression target here — it never defines the engine.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

import pytest

from tests.framework.phase3 import Phase3Harness
from tests.framework.surfaces import ALL_SHAPES

#: Real regression target (loopback-only black-box).
REAL_TARGET = "http://localhost:3010/"


def _target_reachable() -> bool:
    try:
        response = urllib.request.urlopen(REAL_TARGET, timeout=5)
        return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


class TestGenericTargetValidation:
    """The core pipeline operates over every abstract target model."""

    def test_all_target_models_run_through_the_pipeline(self) -> None:
        for shape in ALL_SHAPES:
            harness = Phase3Harness(target=shape.target, mission_id=f"phase3-{shape.name}")
            for event in shape.observations:
                harness.ingest(
                    observation_type=event.observation_type,
                    content=event.content,
                    asset_key=event.asset_key,
                    session_state=event.session_state,
                )
            harness.attack_queue()
            metrics = harness.surface_metrics()
            tasks = harness.task_metrics()
            # Every target model produced discovered surfaces and scheduled
            # assessment tasks — regardless of its technology/object model.
            assert metrics["attack_surfaces_discovered"] >= 3, shape.name
            assert tasks["tasks_generated"] > 0, shape.name
            # The capability matrix is built from the live catalog for every
            # model (not a hardcoded per-target list).
            matrix = harness.capability_matrix()
            assert matrix, shape.name
            assert all("capability" in row for row in matrix), shape.name
            # The pipeline never crashed and every task reached a verdict path.
            assert tasks["tasks_generated"] == sum(tasks["task_statuses"].values()), shape.name

    def test_target_models_are_represented_dynamically(self) -> None:
        shapes_by_kind = {
            "objects": {s.name: s.expected_objects for s in ALL_SHAPES if s.expected_objects},
            "workflows": {s.name: s.expected_workflows for s in ALL_SHAPES if s.expected_workflows},
        }
        for shape in ALL_SHAPES:
            harness = Phase3Harness(target=shape.target, mission_id=f"phase3-{shape.name}")
            for event in shape.observations:
                harness.ingest(
                    observation_type=event.observation_type,
                    content=event.content,
                    asset_key=event.asset_key,
                    session_state=event.session_state,
                )
            for expected_object in shape.expected_objects:
                object_types = {obj.object_type for obj in harness.surface.graph.objects()}
                assert expected_object in object_types, (shape.name, expected_object)
            for expected_workflow in shape.expected_workflows:
                workflow_names = {
                    node.name for node in harness.surface.graph.nodes()
                }
                assert expected_workflow in workflow_names, (shape.name, expected_workflow)
            assert shapes_by_kind  # fixtures carry dynamic objects/workflows

    def test_negative_testing_no_silent_discard(self) -> None:
        """No task is silently discarded; every generated task has a terminal
        status after the attack phase and blocked/failed are explicit."""
        shape = ALL_SHAPES[0]
        harness = Phase3Harness(target=shape.target, mission_id="phase3-negative")
        for event in shape.observations:
            harness.ingest(
                observation_type=event.observation_type,
                content=event.content,
                asset_key=event.asset_key,
            )
        total = harness.surface.queue.total()
        harness.attack_queue()
        statuses = {task.status.value for task in harness.surface.queue.tasks()}
        assert total > 0
        # Every task is now terminal (the non-loopback fixture probes are
        # honestly blocked, never silently skipped).
        assert statuses <= {"completed", "failed", "blocked", "skipped"}, statuses
        assert harness.task_metrics()["tasks_generated"] == total
        # Blocking is blocking: non-loopback probes are recorded, not treated as
        # findings or completion.
        assert not harness.findings
        assert harness.blocked_tasks or not harness._probe_count  # noqa: SLF001

    def test_no_target_coupling_in_core(self) -> None:
        """Core architecture carries no Juice Shop / target-specific references."""
        import re

        root = os.path.join(os.path.dirname(__file__), "..", "..", "src", "hunterx")
        for dirpath, _, files in os.walk(root):
            if "__pycache__" in dirpath:
                continue
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(dirpath, filename)
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for line_number, line in enumerate(handle, 1):
                        assert not re.search(r"(?i)juice|localhost:3010|:3010", line), (
                            f"{path}:{line_number} couples to a specific target"
                        )


class TestRealBlackBoxRegression:
    """Run HunterX against the real loopback target as an arbitrary external
    target: discovery, mapping, attack, verification and exhaustion all derive
    from what HunterX observes — nothing is preconfigured."""

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_assessment_and_exhaustion(self) -> None:
        harness = Phase3Harness(target=REAL_TARGET, probe_timeout_s=3.0, max_tasks=0)
        discovery = harness.real_discovery(max_scripts=3, max_endpoints=80)
        # HunterX discovered the surface itself.
        assert discovery["endpoints_discovered"] >= 10, discovery
        assert harness.surface.graph.node_count() >= 20
        assert harness.surface.queue.total() > 20

        attack = harness.attack_queue()
        assert attack["tasks_executed"] > 0
        assert attack["requests_sent"] > 0
        assert harness.surface.queue.remaining() == 0
        assert harness.task_metrics()["tasks_generated"] == harness.task_metrics()["tasks_executed"] + len(
            harness.blocked_tasks
        ) + len(harness.failed_tasks)

        proof = harness.finalize_exhaustion()
        assert proof["completion_reason"] == "exhausted", proof["reason"]
        assert proof["remaining_attack_tasks"] == 0
        assert all(proof["criteria"].values()), proof["criteria"]

        report = harness.report()
        assert report["completion"]["completion_reason"] == "exhausted"
        assert report["tasks"]["capabilities_considered"] > 0
        matrix = report["capability_matrix"]
        assert matrix, "capability matrix must be built from the live catalog"
        # Evidence of real attack traffic + adaptive feedback.
        assert report["verification"]["probes_executed"] > 0
        assert report["adaptive"]["signal_counts"], "adaptive feedback must be observed"

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_completion_gate_honesty_under_task_cap(self) -> None:
        """With a task cap, the completion gate must NOT report completion while
        applicable work remains — and the queue dump must show it."""
        harness = Phase3Harness(target=REAL_TARGET, probe_timeout_s=3.0, max_tasks=40)
        harness.real_discovery(max_scripts=3, max_endpoints=60)
        harness.attack_queue()
        proof = harness.finalize_exhaustion()
        assert harness.surface.queue.remaining() > 0
        assert proof["completion_reason"] == "not_exhausted", proof["reason"]
        assert not all(proof["criteria"].values())
        assert proof["remaining_attack_tasks"] > 0
        assert proof["queue_dump"], "the completion dump must expose remaining tasks"
        # Machine-readable reason present.
        assert proof["machine_readable_reason"]

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_adaptive_control_observes_real_feedback(self) -> None:
        harness = Phase3Harness(target=REAL_TARGET, probe_timeout_s=3.0, max_tasks=60)
        harness.real_discovery(max_scripts=3, max_endpoints=60)
        harness.attack_queue()
        adaptive = harness.adaptive_metrics()
        # Real feedback samples were collected and the controller produced a
        # deterministic state + bounded controls.
        assert adaptive["signal_counts"]
        assert adaptive["final_state"] in (
            "normal",
            "aggressive",
            "throttled",
            "backing_off",
            "recovering",
            "blocked",
            "resuming",
        )
        assert 1 <= adaptive["concurrency_limit"] <= 8
        assert adaptive["pacing_seconds"] <= 30.0
        assert adaptive["backoff_seconds"] <= 60.0

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_report_is_serializable(self, tmp_path: Any) -> None:
        harness = Phase3Harness(target=REAL_TARGET, probe_timeout_s=3.0, max_tasks=0)
        harness.real_discovery(max_scripts=3, max_endpoints=80)
        harness.attack_queue()
        harness.finalize_exhaustion()
        report = harness.report()
        payload = json.dumps(report, default=str)
        assert payload
        report_path = tmp_path / "phase3-report.json"
        report_path.write_text(payload, encoding="utf-8")
        assert report_path.exists()
        assert report_path.stat().st_size > 0
