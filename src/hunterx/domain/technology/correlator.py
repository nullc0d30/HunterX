# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Technology correlation and conflict detection.

Correlates technology observations from multiple tools/executions into a single
canonical set, merging corroborating facts and surfacing conflicts. The
correlator never silently discards an observation: versions that disagree
across sources are reported as :class:`TechConflict` records with full
provenance, and every out-of-scope or below-threshold observation is counted
rather than dropped silently.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from hunterx.domain.technology.confidence import TechnologyConfidenceEngine, TechnologyConfidencePolicy
from hunterx.domain.technology.models import (
    TechConflict,
    TechnologyEvidence,
    TechnologyObservation,
    VersionConfidence,
    VersionSpec,
)
from hunterx.domain.technology.resolver import TechnologyResolver
from hunterx.domain.technology.scope import TechnologyScopeEnforcer, TechnologyScopePolicy
from hunterx.domain.technology.validator import TechnologyValidator


@dataclass(frozen=True, slots=True)
class TechnologyCorrelationResult:
    """The outcome of correlating a set of technology observations.

    Attributes:
        technologies: canonical, merged technology observations.
        conflicts: observations that disagreed across sources.
        scoped_out: observations removed by scope enforcement.
        dropped: observations removed by confidence/threshold policies.
        merged: number of observation groups that carried corroboration.

    """

    technologies: tuple[TechnologyObservation, ...] = ()
    conflicts: tuple[TechConflict, ...] = ()
    scoped_out: int = 0
    dropped: int = 0
    merged: int = 0


class TechnologyCorrelator:
    """Correlate technology observations into a canonical set.

    Observations sharing a canonical key (same asset + canonical name) are
    merged: sources accumulated, evidence folded and confidence raised by
    corroboration. Distinct versions within a group produce a
    :class:`TechConflict` rather than a silent selection.
    """

    def __init__(
        self,
        *,
        scope: TechnologyScopePolicy | None = None,
        confidence: TechnologyConfidencePolicy | None = None,
        resolver: TechnologyResolver | None = None,
        min_confidence: float = 0.4,
    ) -> None:
        self._scope = scope or TechnologyScopePolicy()
        self._confidence_policy = confidence or TechnologyConfidencePolicy()
        self._confidence = TechnologyConfidenceEngine(self._confidence_policy)
        self._resolver = resolver or TechnologyResolver()
        self._enforcer = TechnologyScopeEnforcer(self._scope)
        self._validator = TechnologyValidator()
        self._min_confidence = min_confidence

    def correlate(
        self,
        observations: Iterable[TechnologyObservation],
        *,
        min_confidence: float | None = None,
    ) -> TechnologyCorrelationResult:
        """Correlate observations into canonical technologies plus conflicts."""
        effective_min = self._min_confidence if min_confidence is None else min_confidence
        scoped_out = 0
        dropped = 0
        grouped: dict[str, list[TechnologyObservation]] = {}
        for observation in observations:
            if not self._enforcer.allows_observation(observation).allowed:
                scoped_out += 1
                continue
            if self._confidence.observation_confidence(observation) < effective_min:
                dropped += 1
                continue
            grouped.setdefault(observation.key(), []).append(observation)

        technologies: list[TechnologyObservation] = []
        conflicts: list[TechConflict] = []
        merged = 0
        for _key, group in grouped.items():
            if len(group) > 1:
                merged += 1
            canonical, conflict = self._merge_group(group)
            technologies.append(canonical)
            if conflict is not None:
                conflicts.append(conflict)

        technologies.sort(key=lambda obs: (obs.asset, obs.canonical_name))
        return TechnologyCorrelationResult(
            technologies=tuple(technologies),
            conflicts=tuple(_dedupe_conflicts(conflicts)),
            scoped_out=scoped_out,
            dropped=dropped,
            merged=merged,
        )

    # -- group merging ------------------------------------------------------

    def _merge_group(self, group: Sequence[TechnologyObservation]) -> tuple[TechnologyObservation, TechConflict | None]:
        """Merge a corroborated group; returns the canonical record + optional conflict."""
        representative = max(group, key=self._confidence.observation_confidence)
        versions = {_version_key(observation) for observation in group if observation.version}
        conflicted = len(versions) > 1
        version_spec = self._best_version_spec(group)
        evidence = _fold_evidence(group)
        canonical = replace(
            representative,
            version_spec=version_spec,
            version=version_spec.value if version_spec is not None else representative.version,
            evidence=evidence,
            source=_join_sources(group),
            confidence=self._confidence.merged_confidence(group, conflicted=conflicted),
            observed_at=_earliest(group),
        )
        conflict = None
        if conflicted:
            selected = max(
                (observation for observation in group if observation.version),
                key=self._confidence.observation_confidence,
            )
            conflict = TechConflict(
                asset=representative.asset,
                technology=representative.canonical_name or representative.raw_name,
                observations=tuple(_observation_dict(observation) for observation in group),
                conflict_type="version",
                selected=selected.version,
                selected_source=selected.tool_id or selected.source,
                reason="conflicting versions reported across sources",
                confidence=self._confidence.observation_confidence(selected),
            )
        return canonical, conflict

    def _best_version_spec(self, group: Sequence[TechnologyObservation]) -> VersionSpec | None:
        """Return the strongest version spec in a group (deterministic)."""
        ranked: list[tuple[float, VersionSpec]] = []
        for observation in group:
            spec = observation.version_spec
            if spec is None or not spec.value:
                continue
            weight = _VERSION_WEIGHTS.get(spec.confidence, 0.0)
            ranked.append((weight, spec))
        if not ranked:
            return None
        ranked.sort(key=lambda pair: (pair[0], pair[1].value))
        return ranked[-1][1]


#: Relative weight of each version confidence for group selection.
_VERSION_WEIGHTS: dict[VersionConfidence, float] = {
    VersionConfidence.CONFIRMED: 4.0,
    VersionConfidence.PROBABLE: 3.0,
    VersionConfidence.RANGE: 2.0,
    VersionConfidence.UNKNOWN: 1.0,
}


def _version_key(observation: TechnologyObservation) -> str:
    return str(observation.version).strip().lower()


def _fold_evidence(group: Sequence[TechnologyObservation]) -> tuple[TechnologyEvidence, ...]:
    """Fold the evidence fragments of a corroborated group (deduplicated)."""
    seen: set[tuple[str, str, str]] = set()
    evidence: list[TechnologyEvidence] = []
    for observation in group:
        for item in observation.evidence:
            key = (item.evidence_type.value, item.value, item.tool_id)
            if key in seen:
                continue
            seen.add(key)
            evidence.append(item)
    return tuple(evidence)


def _join_sources(observations: Sequence[TechnologyObservation]) -> str:
    """Join the distinct sources of a corroborated group."""
    return ",".join(
        sorted({str(getattr(obs, "source", "")) for obs in observations if getattr(obs, "source", "")})
    )


def _earliest(observations: Sequence[TechnologyObservation]) -> str:
    """Return the earliest observation timestamp of a corroborated group."""
    return min(str(getattr(obs, "observed_at", "")) for obs in observations)


def _observation_dict(observation: TechnologyObservation) -> dict[str, Any]:
    """Return the JSON-safe payload of an observation for conflict records."""
    return observation.to_dict()


def _dedupe_conflicts(conflicts: Iterable[TechConflict]) -> list[TechConflict]:
    """Dedupe conflicts that repeat the same asset/technology/selected tuple."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[TechConflict] = []
    for conflict in conflicts:
        key = (conflict.asset, conflict.technology, conflict.selected)
        if key in seen:
            continue
        seen.add(key)
        unique.append(conflict)
    return unique
