# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Live Host & Service Discovery confidence engine.

Assigns a defensible, deterministic confidence score to every live discovery
observation and recomputes it when several tools corroborate the same fact.
Confidence is a pure function of (tool reliability, validation status,
detection method, port/fingerprint evidence strength, corroboration count and
freshness) — the same inputs always yield the same score and the score is
explainable through the factors that contributed to it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from hunterx.domain.livehost.models import (
    LiveHost,
    PortFinding,
    PortState,
    ReachabilityMethod,
    ServiceFinding,
)

#: Default base reliability per tool (``0.2`` unknown tools score low).
_DEFAULT_BASE: dict[str, float] = {
    "nmap": 0.95,
    "masscan": 0.9,
    "naabu": 0.88,
    "tcp-connect": 0.8,
}

#: Multiplicative factor per validation status.
_VALIDATION_FACTORS: Mapping[str, float] = {
    "valid": 1.0,
    "unknown": 0.75,
    "invalid": 0.3,
}

#: Factor per reachability method used for host evidence.
_METHOD_FACTORS: Mapping[ReachabilityMethod, float] = {
    ReachabilityMethod.TCP_SYN: 1.0,
    ReachabilityMethod.TCP_CONNECT: 1.0,
    ReachabilityMethod.APPLICATION: 1.0,
    ReachabilityMethod.ICMP: 0.9,
    ReachabilityMethod.DNS: 0.7,
}

#: Factor per port state (an ambiguous state scores lower).
_STATE_FACTORS: Mapping[PortState, float] = {
    PortState.OPEN: 1.0,
    PortState.CLOSED: 0.9,
    PortState.UNFILTERED: 0.8,
    PortState.FILTERED: 0.7,
    PortState.UNKNOWN: 0.4,
}

#: Factor per service fingerprint method (probed banners are strongest).
_FINGERPRINT_METHOD_FACTORS: Mapping[str, float] = {
    "probed": 1.0,
    "matched": 0.95,
    "syn-ack": 0.7,
    "unknown": 0.5,
}

#: Per-tool corroboration boost applied beyond the strongest tool.
_CORROBORATION_BOOST = 0.08


@dataclass(frozen=True, slots=True)
class LiveConfidencePolicy:
    """Configuration governing live discovery confidence scoring.

    Attributes:
        base: map of ``tool_id`` to base reliability in ``[0, 1]``.
        validation_factors: map of validation status to a multiplicative factor.
        method_factors: factor per :class:`ReachabilityMethod`.
        state_factors: factor per :class:`PortState`.
        fingerprint_method_factors: factor per service fingerprint method.
        corroboration_boost: confidence added per corroborating tool beyond
            the strongest one.
        max_confidence: ceiling applied to every computed score.

    """

    base: Mapping[str, float] = field(default_factory=lambda: dict(_DEFAULT_BASE))
    validation_factors: Mapping[str, float] = field(default_factory=lambda: dict(_VALIDATION_FACTORS))
    method_factors: Mapping[ReachabilityMethod, float] = field(default_factory=lambda: dict(_METHOD_FACTORS))
    state_factors: Mapping[PortState, float] = field(default_factory=lambda: dict(_STATE_FACTORS))
    fingerprint_method_factors: Mapping[str, float] = field(default_factory=lambda: dict(_FINGERPRINT_METHOD_FACTORS))
    corroboration_boost: float = _CORROBORATION_BOOST
    max_confidence: float = 1.0

    def base_for(self, tool_id: str) -> float:
        """Return the base reliability for ``tool_id`` (``0.2`` when unknown)."""
        return self.base.get(tool_id, 0.2)

    def validation_factor(self, status: str) -> float:
        """Return the factor for a validation status (``0.5`` when unset)."""
        return self.validation_factors.get(status, 0.5)

    def method_factor(self, method: ReachabilityMethod) -> float:
        """Return the factor for a reachability method (``0.7`` when unset)."""
        return self.method_factors.get(method, 0.7)

    def state_factor(self, state: PortState) -> float:
        """Return the factor for a port state (``0.5`` when unset)."""
        return self.state_factors.get(state, 0.5)

    def fingerprint_method_factor(self, method: str) -> float:
        """Return the factor for a fingerprint method (``0.5`` when unset)."""
        return self.fingerprint_method_factors.get(method, 0.5)


class LiveConfidenceEngine:
    """Compute and merge confidence scores for live discovery observations.

    Usage::

        engine = LiveConfidenceEngine()
        score = engine.observation_confidence(observation)
        merged = engine.merged_confidence(observations)
    """

    def __init__(self, policy: LiveConfidencePolicy | None = None) -> None:
        self._policy = policy or LiveConfidencePolicy()

    @property
    def policy(self) -> LiveConfidencePolicy:
        """Return the active policy."""
        return self._policy

    def observation_confidence(self, observation: object) -> float:
        """Return the confidence of a single observation."""
        base = self._policy.base_for(getattr(observation, "tool_id", ""))
        validation = self._policy.validation_factor(getattr(observation, "validation_status", "valid"))
        factor = self._evidence_factor(observation)
        return _clamp(base * validation * factor, self._policy)

    def merged_confidence(self, observations: Sequence[object]) -> float:
        """Compute the confidence of a corroborated observation group.

        Uses the strongest individual score and adds a boost for every distinct
        corroborating tool beyond the first.
        """
        if not observations:
            return 0.0
        strongest = max(self.observation_confidence(observation) for observation in observations)
        distinct_tools = {getattr(observation, "tool_id", "") for observation in observations}
        distinct_tools.discard("")
        boost = self._policy.corroboration_boost * max(0, len(distinct_tools) - 1)
        return _clamp(strongest + boost, self._policy)

    def historical_confidence(self, base: float, *, observations: int, stable: bool) -> float:
        """Adjust a confidence for historical stability.

        Observations that have been seen many times or that have remained stable
        across runs are more trustworthy.
        """
        stability = 1.0 if stable else 0.9
        history = min(1.0, 0.8 + 0.05 * max(0, observations - 1))
        return _clamp(base * stability * history, self._policy)

    def freshness_confidence(self, base: float, *, age_hours: float) -> float:
        """Decay a confidence score as an observation ages.

        ``age_hours <= 0`` yields no decay; older observations fade toward a
        floor of ``0.5 * base``.
        """
        if age_hours <= 0:
            return _clamp(base, self._policy)
        factor = max(0.5, 1.0 - age_hours / 24.0)
        return _clamp(base * factor, self._policy)

    def _evidence_factor(self, observation: object) -> float:
        """Return the evidence-strength factor for an observation kind."""
        if isinstance(observation, LiveHost):
            methods = observation.methods
            method = methods[0] if methods else ReachabilityMethod.TCP_CONNECT
            return self._policy.method_factor(method)
        if isinstance(observation, PortFinding):
            return self._policy.state_factor(observation.state)
        if isinstance(observation, ServiceFinding):
            return self._policy.fingerprint_method_factor(observation.fingerprint_method)
        return 1.0


def _clamp(value: float, policy: LiveConfidencePolicy) -> float:
    """Clamp ``value`` into ``[0, max_confidence]``."""
    return max(0.0, min(policy.max_confidence, value))
