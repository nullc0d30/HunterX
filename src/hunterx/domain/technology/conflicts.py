# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology conflict resolution.

Deterministic resolution of conflicting technology observations (mostly
conflicting versions of the same product on the same asset). Every observation
is preserved on the conflict record; the canonical value is selected by a
configured strategy — ``most-confident`` (default), ``most-sources`` or
``most-recent`` — and the reason is recorded so downstream consumers can trace
why one value won.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from hunterx.domain.technology.confidence import TechnologyConfidenceEngine, TechnologyConfidencePolicy
from hunterx.domain.technology.models import TechConflict, TechnologyObservation

#: Supported deterministic resolution strategies.
_STRATEGIES = ("most-confident", "most-sources", "most-recent")


@dataclass(frozen=True, slots=True)
class ConflictResolution:
    """The outcome of resolving one conflicting observation group.

    Attributes:
        conflict: the preserved conflict record.
        selected_value: the canonical value chosen.
        selected_source: provenance of the chosen value.
        reason: human-readable explanation.

    """

    conflict: TechConflict
    selected_value: str = ""
    selected_source: str = ""
    reason: str = ""


class TechnologyConflictResolver:
    """Resolve conflicting technology observations deterministically.

    Usage::

        resolver = TechnologyConflictResolver()
        resolution = resolver.resolve(observations)
    """

    def __init__(
        self,
        *,
        strategy: str = "most-confident",
        confidence: TechnologyConfidencePolicy | None = None,
    ) -> None:
        if strategy not in _STRATEGIES:
            raise ValueError(f"unknown conflict strategy '{strategy}'")
        self._strategy = strategy
        self._confidence = TechnologyConfidenceEngine(confidence)

    @property
    def strategy(self) -> str:
        """Return the active resolution strategy."""
        return self._strategy

    def resolve(self, observations: Sequence[TechnologyObservation]) -> ConflictResolution | None:
        """Resolve a conflicting group, returning the resolution (or ``None``)."""
        if not observations:
            return None
        distinct_values = {_value(observation) for observation in observations}
        if len(distinct_values) <= 1:
            return None
        selected = self._select(observations)
        conflict = TechConflict(
            asset=_asset(observations[0]),
            technology=_technology(observations[0]),
            observations=tuple(observation.to_dict() for observation in observations),
            conflict_type="version",
            selected=selected.version,
            selected_source=selected.tool_id or selected.source,
            reason=_reason(self._strategy),
            confidence=self._confidence.observation_confidence(selected),
        )
        return ConflictResolution(
            conflict=conflict,
            selected_value=selected.version,
            selected_source=selected.tool_id or selected.source,
            reason=_reason(self._strategy),
        )

    def resolve_many(self, groups: Mapping[str, Sequence[TechnologyObservation]]) -> list[ConflictResolution]:
        """Resolve every conflicting group in a mapping of key -> observations."""
        resolutions: list[ConflictResolution] = []
        for _key, group in groups.items():
            resolution = self.resolve(group)
            if resolution is not None:
                resolutions.append(resolution)
        resolutions.sort(key=lambda item: (item.conflict.asset, item.conflict.technology))
        return resolutions

    def _select(self, observations: Sequence[TechnologyObservation]) -> TechnologyObservation:
        """Select the winning observation under the configured strategy."""
        if self._strategy == "most-sources":
            return max(observations, key=lambda obs: (len(obs.evidence), self._confidence.observation_confidence(obs)))
        if self._strategy == "most-recent":
            return max(observations, key=lambda obs: str(obs.observed_at))
        return max(observations, key=self._confidence.observation_confidence)


def _value(observation: TechnologyObservation) -> str:
    return str(observation.version).strip().lower()


def _asset(observation: TechnologyObservation) -> str:
    return observation.asset


def _technology(observation: TechnologyObservation) -> str:
    return observation.canonical_name or observation.raw_name


def _reason(strategy: str) -> str:
    return {
        "most-confident": "selected by highest confidence",
        "most-sources": "selected by most supporting evidence sources",
        "most-recent": "selected by most recent observation",
    }[strategy]
