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


__all__ = ["EmptyHypothesisModel", "ScriptedHypothesisModel"]
