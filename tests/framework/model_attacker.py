# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Deterministic scripted model fixtures for the autonomous attack loop.

A scripted model implements the same :class:`AIPort` interface the real
providers expose, so it participates in the *real* execution loop: the model
output feeds the reasoner, the reasoner's hypotheses become real assessment
tasks, the engine executes them, and results feed back into the next reasoning
round.
"""

from __future__ import annotations

import json
from typing import Any


class ScriptedHypothesisModel:
    """Return a scripted sequence of JSON hypothesis sets per reasoning round.

    Args:
        script: list of hypothesis dicts per round; the final empty round is
            the model's "no further attack path" signal (genuine exhaustion).
        fail_after: raise a provider error after this many calls (``0`` = never)
            to exercise model-failure handling.

    """

    def __init__(self, script: list[list[dict[str, Any]]], *, fail_after: int = 0) -> None:
        self._script = list(script)
        self._fail_after = fail_after
        self.prompts: list[str] = []
        self.calls = 0

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        self.prompts.append(prompt)
        self.calls += 1
        if self._fail_after and self.calls >= self._fail_after:
            raise RuntimeError("provider unavailable")
        index = min(self.calls - 1, len(self._script) - 1)
        return json.dumps({"hypotheses": self._script[index]})

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return [0.1, 0.2, 0.3]


class EmptyHypothesisModel:
    """A model that always concludes no further attack path remains."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        self.calls += 1
        return json.dumps({"hypotheses": []})

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


class ContextAwareHypothesisModel:
    """A deterministic model that reasons over the prompt context.

    Implements the same :class:`AIPort` interface as every real provider, so it
    participates in the real loop. It proposes one hypothesis per round against
    an unproposed discovered surface — preferring a discovered parameter, then
    falling back to a default vector on endpoint-level surfaces — and concludes
    ``[]`` once no further path remains (the "no further attack path" signal
    the exhaustion semantics require).
    """

    def __init__(self, capability: str = "sql-injection") -> None:
        self.calls = 0
        self.capability = capability
        self._proposed: set[tuple[str, str]] = set()
        self._covered_surfaces: set[str] = set()

    def complete(self, prompt: str, *, model: str | None = None, temperature: float = 0.0) -> str:  # noqa: ARG002
        self.calls += 1
        surfaces = _parse_prompt_surfaces(prompt)
        candidate: tuple[str, str] | None = None
        for item in surfaces:
            for parameter in item["parameters"]:
                if (item["surface"], parameter) not in self._proposed:
                    candidate = (item["surface"], parameter)
                    break
            if candidate is not None:
                break
        if candidate is None:
            for item in surfaces:
                if item["surface"] not in self._covered_surfaces:
                    candidate = (item["surface"], "q")
                    break
        if candidate is None:
            return json.dumps({"hypotheses": []})
        self._proposed.add(candidate)
        self._covered_surfaces.add(candidate[0])
        surface, parameter = candidate
        return json.dumps(
            {
                "hypotheses": [
                    {
                        "capability": self.capability,
                        "surface": surface,
                        "attack_vector": parameter,
                        "attack_strategy": "error-based",
                        "expected_signal": "error_based",
                        "priority": 0.8,
                        "confidence": 0.6,
                        "reasoning_context": "differential probing of a discovered surface",
                    }
                ]
            }
        )

    def embed(self, text: str) -> list[float]:  # noqa: ARG002
        return []


def _parse_prompt_surfaces(prompt: str) -> list[dict[str, Any]]:
    import re

    surfaces: list[dict[str, Any]] = []
    in_section = False
    for line in prompt.splitlines():
        if line.startswith("DISCOVERED SURFACES:"):
            in_section = True
            continue
        if in_section and line.strip() == "":
            break
        if in_section and line.startswith("- surface="):
            match = re.match(r"- surface=(.+?) parameters=(.*?) layer=", line)
            if match:
                parameters = [part.strip() for part in match.group(2).split(",") if part.strip()]
                surfaces.append({"surface": match.group(1), "parameters": parameters})
    return surfaces


__all__ = ["ContextAwareHypothesisModel", "EmptyHypothesisModel", "ScriptedHypothesisModel"]
