# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""API observation validation.

Validates raw API intelligence observations before they enter correlation:
rejects empty/invalid records, filters low-confidence records below the
strategy's minimum confidence and drops observations whose origin is out of
scope. The validator is pure and deterministic.
"""

from __future__ import annotations

from typing import Any

from hunterx.domain.api.models import (
    APIHostObservation,
    ApiOperationObservation,
    APISpecObservation,
)
from hunterx.domain.api.scope import ApiScopeEnforcer, ScopeDecision


class ApiValidator:
    """Filter invalid, low-confidence and out-of-scope API observations.

    Usage::

        validator = ApiValidator(enforcer=ApiScopeEnforcer(policy), min_confidence=0.25)
        kept = [item for item in raw if validator.accepts(item).allowed]
    """

    def __init__(
        self,
        *,
        enforcer: ApiScopeEnforcer | None = None,
        min_confidence: float = 0.0,
        max_operations: int = 2000,
    ) -> None:
        self._enforcer = enforcer or ApiScopeEnforcer()
        self._min_confidence = min_confidence
        self._max_operations = max_operations

    def accepts(self, observation: Any) -> ScopeDecision:
        """Decide whether an observation is valid and in scope."""
        if observation is None:
            return ScopeDecision(False, "empty observation")

        origin = getattr(observation, "origin_key", "")
        if not origin:
            return ScopeDecision(False, "empty origin")

        confidence = float(getattr(observation, "confidence", 1.0) or 0.0)
        if confidence < self._min_confidence:
            return ScopeDecision(
                False,
                f"confidence {confidence:.2f} below minimum {self._min_confidence:.2f}",
            )

        if isinstance(observation, ApiOperationObservation) and (not observation.path or not observation.method):
            return ScopeDecision(False, "operation missing path or method")

        if isinstance(observation, APIHostObservation) and not observation.origin_key:
            return ScopeDecision(False, "host missing origin")

        if isinstance(observation, APISpecObservation) and not observation.source_url:
            return ScopeDecision(False, "spec missing source URL")

        return self._enforcer.allows_observation(origin)

    def accepts_many(self, observations: list[Any]) -> list[Any]:
        """Return only the accepted observations."""
        kept: list[Any] = []
        for item in observations:
            if self.accepts(item).allowed:
                kept.append(item)
        return kept
