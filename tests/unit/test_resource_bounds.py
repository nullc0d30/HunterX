# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: bounded in-memory state.

Verifies that unbounded growth of observations / hypotheses / evidence /
decisions is prevented while important evidence (open hypotheses, validated
findings, the most recent observations) is preserved. The durable system of
record is the database — the in-memory aggregate is only the working set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunterx.resource.bounds import (
    apply_mission_bounds,
    content_bytes,
    trim_hypotheses,
    trim_observations,
    trim_observations_by_bytes,
    truncate_content,
)
from hunterx.resource.config import ResourceConfig


@dataclass
class _Hypothesis:
    hypothesis_id: str = ""
    state: str = "proposed"
    priority: float = 0.5
    confidence: float = 0.5
    supporting_evidence: tuple[str, ...] = ()
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Obs:
    observation_id: str = ""


@dataclass
class _Context:
    observations: list[Any] = field(default_factory=list)
    decisions: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)
    tool_executions: list[Any] = field(default_factory=list)
    attack_paths: list[Any] = field(default_factory=list)
    history: list[Any] = field(default_factory=list)
    endpoints: dict[str, Any] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)
    services: dict[str, Any] = field(default_factory=dict)
    assets: dict[str, Any] = field(default_factory=dict)
    technologies: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Mission:
    observations: list[Any] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    decisions: list[Any] = field(default_factory=list)
    trace: list[Any] = field(default_factory=list)
    negative_evidence: list[Any] = field(default_factory=list)
    context: _Context = field(default_factory=_Context)


class TestBoundedObservations:
    def test_observations_trim_to_cap_keeping_most_recent(self) -> None:
        observations = [_Obs(observation_id=f"o{i}") for i in range(50)]
        trim_observations(observations, 10)
        assert len(observations) == 10
        assert observations[0].observation_id == "o40"
        assert observations[-1].observation_id == "o49"

    def test_under_cap_is_untouched(self) -> None:
        observations = [_Obs(observation_id=f"o{i}") for i in range(5)]
        trim_observations(observations, 10)
        assert len(observations) == 5


class TestBoundedHypotheses:
    def test_open_hypotheses_are_never_evicted(self) -> None:
        hypotheses = [_Hypothesis(hypothesis_id=f"h{i}", state="proposed", priority=0.1) for i in range(20)]
        # 15 open hypotheses with a cap of 10: terminal are dropped first, but
        # there are none — so the lowest-priority open ones go.
        trim_hypotheses(hypotheses, 10)
        assert len(hypotheses) == 10
        assert all(h.state == "proposed" for h in hypotheses)

    def test_terminal_hypotheses_are_evicted_first(self) -> None:
        hypotheses = [_Hypothesis(hypothesis_id=f"h{i}", state="refuted", priority=0.5) for i in range(15)]
        hypotheses.append(_Hypothesis(hypothesis_id="open1", state="supported", priority=0.9))
        trim_hypotheses(hypotheses, 2)
        assert len(hypotheses) == 2
        ids = {h.hypothesis_id for h in hypotheses}
        assert "open1" in ids

    def test_validated_findings_are_preserved(self) -> None:
        hypotheses = [_Hypothesis(hypothesis_id=f"h{i}", state="disproved", priority=0.5) for i in range(15)]
        # A "finding-bearing" terminal hypothesis (important) must survive.
        hypotheses.append(_Hypothesis(hypothesis_id="kept", state="refuted", priority=0.5, provenance={"finding": True}))
        trim_hypotheses(hypotheses, 1)
        assert [h.hypothesis_id for h in hypotheses] == ["kept"]


class TestMissionBounds:
    def test_apply_mission_bounds_trims_all_collections(self) -> None:
        config = ResourceConfig(
            max_observations_in_memory=5,
            max_hypotheses_in_memory=5,
            max_decisions_in_memory=5,
            max_evidence_in_memory=5,
            max_tool_executions_in_memory=5,
            max_trace_in_memory=5,
            max_negative_evidence_in_memory=5,
        )
        mission = _Mission(
            observations=[_Obs(observation_id=f"o{i}") for i in range(20)],
            hypotheses=[_Hypothesis(hypothesis_id=f"h{i}", state="refuted") for i in range(20)],
            decisions=[f"d{i}" for i in range(20)],
            trace=[f"t{i}" for i in range(20)],
            negative_evidence=[f"n{i}" for i in range(20)],
            context=_Context(
                observations=[f"o{i}" for i in range(20)],
                decisions=[f"d{i}" for i in range(20)],
                findings=[f"f{i}" for i in range(20)],
                tool_executions=[f"e{i}" for i in range(20)],
                attack_paths=[f"a{i}" for i in range(20)],
                history=[f"h{i}" for i in range(20)],
                endpoints={f"ep{i}": i for i in range(20)},
                parameters={f"p{i}": i for i in range(20)},
            ),
        )
        apply_mission_bounds(mission, config)
        assert len(mission.observations) == 5
        assert len(mission.hypotheses) == 5
        assert len(mission.decisions) == 5
        assert len(mission.trace) == 5
        assert len(mission.negative_evidence) == 5
        assert len(mission.context.observations) == 5
        assert len(mission.context.findings) == 5
        assert len(mission.context.tool_executions) == 5
        assert len(mission.context.endpoints) == 5
        assert len(mission.context.parameters) == 5

    def test_apply_mission_bounds_keeps_open_hypotheses(self) -> None:
        config = ResourceConfig(max_hypotheses_in_memory=3)
        hypotheses = [_Hypothesis(hypothesis_id=f"ref{i}", state="refuted", priority=0.1) for i in range(10)]
        hypotheses.append(_Hypothesis(hypothesis_id="open1", state="supported", priority=0.9))
        mission = _Mission(hypotheses=hypotheses)
        apply_mission_bounds(mission, config)
        ids = {h.hypothesis_id for h in mission.hypotheses}
        assert "open1" in ids

    def test_none_mission_is_safe(self) -> None:
        apply_mission_bounds(None, ResourceConfig())


class TestByteBounds:
    def test_content_bytes_is_measured(self) -> None:
        content = {"blob": "x" * 10000, "ports": list(range(100))}
        assert content_bytes(content) >= 10000

    def test_truncate_content_caps_serialized_size(self) -> None:
        content = {"blob": "x" * (1024 * 1024), "ports": list(range(500))}
        truncated = truncate_content(content, 4096)
        assert content_bytes(truncated) <= 4096
        # Keys are preserved (JSON-safe summary, never silent truncation).
        assert "blob" in truncated
        assert "ports" in truncated

    def test_truncate_content_keeps_small_payload_unchanged(self) -> None:
        content = {"a": 1}
        assert truncate_content(content, 4096) is content

    def test_trim_observations_by_bytes_drops_oldest(self) -> None:
        class Obs:
            def __init__(self, content): self.content = content
        observations = [Obs({"blob": "y" * 2000}) for _ in range(20)]
        trim_observations_by_bytes(observations, 8000)
        assert len(observations) < 20
        assert sum(content_bytes(o.content) for o in observations) <= 8000

    def test_apply_bounds_trims_services_assets_technologies(self) -> None:
        config = ResourceConfig(max_services_in_memory=5, max_assets_in_memory=5, max_technologies_in_memory=5)
        mission = _Mission(
            context=_Context(
                services={f"s{i}": {"identity": str(i)} for i in range(30)},
                assets={f"a{i}": {"key": str(i)} for i in range(30)},
                technologies={f"t{i}": {"key": str(i)} for i in range(30)},
            )
        )
        apply_mission_bounds(mission, config)
        assert len(mission.context.services) == 5
        assert len(mission.context.assets) == 5
        assert len(mission.context.technologies) == 5


__all__ = []
