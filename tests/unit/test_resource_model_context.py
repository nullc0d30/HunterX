# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Resource-governance tests: bounded model reasoning context.

The model-driven attacker must receive an efficient summarized state, never an
ever-growing full mission history: observations, findings, adjacent paths and
disproven fingerprints fed to the prompt are all bounded, so both the prompt
size and the attacker's in-memory retention are bounded regardless of how long
the autonomous loop runs.
"""

from __future__ import annotations

from hunterx.domain.model_attacker.learning import LearningContext
from hunterx.domain.model_attacker.reasoner import build_prompt


class TestBoundedLearningContext:
    def test_observations_are_bounded(self) -> None:
        context = LearningContext(max_observations=5)
        for index in range(50):
            context.record_observation(hypothesis_id=f"h{index}", capability="xss", surface="s", signal="reflected", supported=True)
        assert len(context.observations) == 5
        assert context.observations[-1]["observation_id"]  # most recent retained

    def test_findings_and_adjacent_paths_are_bounded(self) -> None:
        context = LearningContext(max_findings=3, max_paths=4)
        for index in range(20):
            finding = {"vulnerability_class": "xss", "surface": f"endpoint-{index}", "vector": "q"}
            context.record_finding(finding, related=[{"capability": "xss", "surface": f"path-{index}", "attack_vector": "id"}])
        assert len(context.validated_findings) == 3
        assert len(context.adjacent_paths) == 4

    def test_disproven_fingerprints_are_bounded(self) -> None:
        context = LearningContext(max_disproven=10)
        for index in range(50):
            context.remember_disproven(f"fp-{index}")
        assert len(context.disproven_fingerprints) == 10

    def test_summary_never_grows_past_caps(self) -> None:
        context = LearningContext(max_observations=7, max_findings=2, max_paths=3, max_disproven=4)
        for index in range(30):
            context.record_observation(hypothesis_id="", capability="sql-injection", surface="s", signal="error_based", supported=False)
            context.record_finding(
                {"vulnerability_class": "sql-injection", "surface": f"ep-{index}", "vector": "q"},
                related=[{"capability": "sql-injection", "surface": f"adj-{index}", "attack_vector": "id"}],
            )
            context.remember_disproven(f"fp-{index}")
        summary = context.summary()
        assert len(summary["observations"]) <= 7
        assert len(summary["validated_findings"]) <= 2
        assert len(summary["adjacent_paths"]) <= 3
        assert len(summary["disproven_hypotheses"]) <= 4


class TestBoundedPrompt:
    def test_prompt_stays_bounded_with_huge_context(self) -> None:
        context = {
            "target": "https://example.com",
            "session_state": "anonymous",
            "surfaces": [{"surface": f"ep-{i}", "parameters": ["q", "id"], "layer": "surface"} for i in range(500)],
            "catalog": ["xss", "sql-injection", "ssrf", "idor"],
            "observations": [{"capability": "xss", "surface": f"s{i}", "signal": "reflected", "supported": True} for i in range(500)],
            "findings": [{"vulnerability_class": "xss", "surface": f"f{i}", "vector": "q", "severity": "high"} for i in range(500)],
            "adjacent_paths": [{"capability": "xss", "surface": f"a{i}", "attack_vector": "q", "reason": "adjacent"} for i in range(500)],
            "disproven": [f"fp-{i}" for i in range(1000)],
        }
        prompt = build_prompt(context)
        # 100 surfaces / 60 observations / 20 findings / 30 paths / 200 disproven.
        assert prompt.count("\n- ") < 500
        assert "fp-0" not in prompt  # only the most recent 200 disproven fingerprints remain
        assert "fp-998" in prompt

    def test_prompt_includes_latest_evidence(self) -> None:
        context = {
            "target": "https://example.com",
            "session_state": "anonymous",
            "surfaces": [{"surface": "ep-1", "parameters": ["q"], "layer": "surface"}],
            "catalog": ["xss"],
            "observations": [{"capability": "xss", "surface": "ep-1", "signal": "reflected", "supported": True}],
            "findings": [],
            "adjacent_paths": [],
            "disproven": [],
        }
        prompt = build_prompt(context)
        assert "ep-1" in prompt
        assert "reflected" in prompt


__all__ = []
