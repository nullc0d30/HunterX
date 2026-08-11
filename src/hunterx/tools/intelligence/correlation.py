# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Evidence correlation (Sprint 023).

Correlates canonical observations across tools, deduplicates observations
that share a canonical identity, and preserves conflicting evidence instead of
averaging it. Conflicting observations always remain available for validation
or proof-strategy selection — they are never merged into a single value.
"""

from __future__ import annotations

from datetime import UTC, datetime

from hunterx.domain.tool_intelligence import (
    CanonicalObservation,
    ConflictingToolEvidence,
    CorrelatedEvidenceChain,
    EvidenceStrength,
    ToolConfidenceCeiling,
)


class EvidenceCorrelator:
    """Correlate, deduplicate and detect conflict in canonical observations.

    Usage::

        correlator = EvidenceCorrelator()
        correlator.ingest(observation)
        chains = correlator.correlated_chains()
        conflicts = correlator.conflicts()
    """

    def __init__(self, ceilings: dict[str, ToolConfidenceCeiling] | None = None) -> None:
        self._observations: list[CanonicalObservation] = []
        self._ceilings = ceilings or {}

    def ingest(self, observation: CanonicalObservation) -> None:
        """Add an observation to the correlator."""
        self._observations.append(observation)

    def ingest_many(self, observations: list[CanonicalObservation]) -> None:
        """Add several observations to the correlator."""
        self._observations.extend(observations)

    def observations(self) -> tuple[CanonicalObservation, ...]:
        """Return all ingested observations."""
        return tuple(self._observations)

    def deduplicate(self) -> list[CanonicalObservation]:
        """Return a de-duplicated list of observations.

        Observations that share a ``correlation_key`` are collapsed to a single
        representative (the highest-confidence one). Observations without a
        correlation key are kept as-is.
        """
        best: dict[str, CanonicalObservation] = {}
        for observation in self._observations:
            key = observation.correlation_key
            if not key:
                continue
            current = best.get(key)
            if current is None or observation.confidence > current.confidence:
                best[key] = observation
        kept = [observation for observation in self._observations if not observation.correlation_key]
        return kept + list(best.values())

    def correlated_chains(self) -> list[CorrelatedEvidenceChain]:
        """Group observations by correlation key into evidence chains.

        The strongest evidence strength observed drives the chain, and the
        aggregate confidence respects each contributing tool's ceiling.
        """
        groups: dict[str, list[CanonicalObservation]] = {}
        for observation in self._observations:
            key = observation.correlation_key
            if not key:
                continue
            groups.setdefault(key, []).append(observation)

        chains: list[CorrelatedEvidenceChain] = []
        for index, (key, items) in enumerate(sorted(groups.items())):
            tools = tuple(sorted({item.tool_id for item in items}))
            strength = self._strongest(items)
            confidence = self._aggregate_confidence(items)
            chains.append(
                CorrelatedEvidenceChain(
                    chain_id=f"chain-{index}",
                    correlation_key=key,
                    observations=tuple(items),
                    tools=tools,
                    vulnerability_classes=self._vulnerability_classes(items),
                    strength=strength,
                    proof_candidate=strength is EvidenceStrength.PROOF,
                    confidence=confidence,
                )
            )
        return chains

    def conflicts(self) -> list[ConflictingToolEvidence]:
        """Return conflicting evidence groups (same key, disagreeing tools).

        Conflict is defined as two or more tools reporting the same canonical
        key with different normalized values. The observations are preserved in
        full — never averaged.
        """
        groups: dict[str, list[CanonicalObservation]] = {}
        for observation in self._observations:
            key = observation.correlation_key
            if not key:
                continue
            groups.setdefault(key, []).append(observation)

        conflicts: list[ConflictingToolEvidence] = []
        for key, items in groups.items():
            by_tool: dict[str, CanonicalObservation] = {}
            for item in items:
                if item.tool_id not in by_tool:
                    by_tool[item.tool_id] = item
            normalized_values = {item.normalized_value for item in by_tool.values()}
            if len(by_tool) >= 2 and len(normalized_values) >= 2:
                conflicts.append(
                    ConflictingToolEvidence(
                        correlation_key=key,
                        target=items[0].target_id,
                        vulnerability_class=self._vulnerability_classes(items)[0]
                        if self._vulnerability_classes(items)
                        else "",
                        observations=tuple(items),
                        tools=tuple(sorted(by_tool)),
                        detected_at=_utc_now(),
                    )
                )
        return conflicts

    def _strongest(self, items: list[CanonicalObservation]) -> EvidenceStrength:
        strength = EvidenceStrength.DETECTION
        for item in items:
            # Inferred strength: a tool that proves is stronger than one that
            # only detects. This stays deterministic and reversible.
            if item.observation_kind == "vulnerability" or item.source == "proof":
                strength = EvidenceStrength.PROOF
            elif item.confidence >= 0.9 and strength is EvidenceStrength.DETECTION:
                strength = EvidenceStrength.BEHAVIORAL
        return strength

    def _aggregate_confidence(self, items: list[CanonicalObservation]) -> float:
        if not items:
            return 0.0
        best = 0.0
        for item in items:
            ceiling = self._ceilings.get(item.tool_id)
            capped = min(item.confidence, ceiling.proof_ceiling if ceiling else 1.0)
            best = max(best, capped)
        return round(best, 4)

    @staticmethod
    def _vulnerability_classes(items: list[CanonicalObservation]) -> tuple[str, ...]:
        classes: list[str] = []
        for item in items:
            for value in item.provenance.get("vulnerability_classes", "").split(","):
                if value and value not in classes:
                    classes.append(value)
        return tuple(classes)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = ["EvidenceCorrelator"]
