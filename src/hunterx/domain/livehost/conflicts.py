# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live discovery conflict resolution policy.

When several observations of the same group disagree (e.g.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from hunterx.domain.livehost.confidence import LiveConfidenceEngine, LiveConfidencePolicy
from hunterx.domain.livehost.correlator import _Observable
from hunterx.domain.livehost.models import DiscoveryConflict

__all__ = ["DiscoveryConflict", "LiveConflictResolver"]

#: Resolution strategies.
_MOST_CONFIDENT = "most-confident"
_MOST_RECENT = "most-recent"

_STRATEGIES = (_MOST_CONFIDENT, _MOST_RECENT)


@dataclass(frozen=True, slots=True)
class LiveConflictResolver:
    """Resolve which observation of a conflicting group is canonical.

    Attributes:
        strategy: ``most-confident`` (default) or ``most-recent``.

    """

    strategy: str = _MOST_CONFIDENT

    def __post_init__(self) -> None:
        if self.strategy not in _STRATEGIES:
            raise ValueError(f"unknown conflict strategy '{self.strategy}'")

    def select(self, conflict: DiscoveryConflict, candidates: Sequence[_Observable]) -> object:
        """Return the canonical observation for a conflicting group.

        ``candidates`` are the observations sharing the conflict's group. The
        selected observation keeps full provenance; losers remain visible
        through the :class:`DiscoveryConflict` returned by the correlator.
        """
        if not candidates:
            raise ValueError("cannot resolve a conflict without candidates")
        if self.strategy == _MOST_RECENT:
            return max(candidates, key=lambda observation: observation.observed_at)
        engine = LiveConfidenceEngine(LiveConfidencePolicy())
        return max(candidates, key=engine.observation_confidence)

    def resolve(
        self,
        conflict: DiscoveryConflict,
        candidates: Sequence[_Observable],
        confidence: LiveConfidencePolicy | None = None,
    ) -> object:
        """Resolve a conflict using the configured strategy.

        The ``confidence`` policy is used for the ``most-confident`` strategy
        when provided.
        """
        if self.strategy != _MOST_CONFIDENT:
            return self.select(conflict, candidates)
        engine = LiveConfidenceEngine(confidence)
        return max(candidates, key=engine.observation_confidence)
