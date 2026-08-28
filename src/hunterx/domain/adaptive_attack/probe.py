# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Attack probe planning and bounded escalation.

Phase 2. Builds the per-surface attack probe plan as an explicit strategy
ladder — baseline → probe → differential analysis → stronger applicable
strategy → verification — while keeping payload volume and mutation depth
bounded by an :class:`AggressionProfile`. Escalation is bounded: the ceiling is
``MAXIMUM`` and the profile never hands an unbounded payload set to a tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from hunterx.domain.adaptive_attack.enums import AggressionLevel, AttackVector
from hunterx.domain.attack_surface.models import SurfaceContext
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso


class ProbeStep(StrEnum):
    """Canonical steps of the aggressive-but-bounded probe strategy ladder."""

    BASELINE = "baseline"
    PROBE = "probe"
    DIFFERENTIAL_ANALYSIS = "differential_analysis"
    STRONGER_STRATEGY = "stronger_strategy"
    VERIFICATION = "verification"

    @classmethod
    def ladder(cls) -> tuple[ProbeStep, ...]:
        """Return the canonical strategy ladder."""
        return (
            cls.BASELINE,
            cls.PROBE,
            cls.DIFFERENTIAL_ANALYSIS,
            cls.STRONGER_STRATEGY,
            cls.VERIFICATION,
        )


@dataclass(frozen=True, slots=True)
class AggressionProfile:
    """Bounded attack-depth profile for an aggression tier.

    Attributes:
        level: the aggression tier.
        payload_budget: maximum payloads per probe (hard bound).
        mutation_depth: maximum controlled request mutations.
        timeout_seconds: per-request timeout ceiling.
        follow_redirects: whether redirects are followed (bounded hops).
        retry_limit: bounded retries per probe.

    """

    level: AggressionLevel
    payload_budget: int
    mutation_depth: int
    timeout_seconds: float
    follow_redirects: bool
    retry_limit: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "level": self.level.value,
            "payload_budget": self.payload_budget,
            "mutation_depth": self.mutation_depth,
            "timeout_seconds": self.timeout_seconds,
            "follow_redirects": self.follow_redirects,
            "retry_limit": self.retry_limit,
        }


#: Bounded profiles per aggression tier. Every budget is a hard ceiling —
#: "aggressive" raises coverage, never floods the target.
_PROFILES: dict[AggressionLevel, AggressionProfile] = {
    AggressionLevel.LOW: AggressionProfile(
        level=AggressionLevel.LOW,
        payload_budget=5,
        mutation_depth=1,
        timeout_seconds=10.0,
        follow_redirects=False,
        retry_limit=1,
    ),
    AggressionLevel.MEDIUM: AggressionProfile(
        level=AggressionLevel.MEDIUM,
        payload_budget=12,
        mutation_depth=2,
        timeout_seconds=15.0,
        follow_redirects=True,
        retry_limit=2,
    ),
    AggressionLevel.HIGH: AggressionProfile(
        level=AggressionLevel.HIGH,
        payload_budget=25,
        mutation_depth=3,
        timeout_seconds=20.0,
        follow_redirects=True,
        retry_limit=3,
    ),
    AggressionLevel.MAXIMUM: AggressionProfile(
        level=AggressionLevel.MAXIMUM,
        payload_budget=50,
        mutation_depth=4,
        timeout_seconds=30.0,
        follow_redirects=True,
        retry_limit=4,
    ),
}


def profile_for(level: AggressionLevel) -> AggressionProfile:
    """Return the bounded aggression profile for ``level``."""
    return _PROFILES[level]


def bounded_payloads(payloads: tuple[str, ...] | list[str], level: AggressionLevel) -> tuple[str, ...]:
    """Return ``payloads`` truncated to the aggression tier's budget.

    This is the hard bound that prevents uncontrolled payload floods while
    still expanding coverage at higher aggression tiers.
    """
    budget = profile_for(level).payload_budget
    return tuple(payloads[:budget])


def bounded_mutations(mutations: tuple[dict[str, Any], ...] | list[dict[str, Any]], level: AggressionLevel) -> tuple[dict[str, Any], ...]:
    """Return ``mutations`` truncated to the aggression tier's depth bound."""
    depth = profile_for(level).mutation_depth
    return tuple(mutations[:depth])


@dataclass(slots=True)
class AttackProbePlan:
    """A bounded attack plan for one ``(surface, capability, context)``.

    Attributes:
        plan_id: stable plan identifier.
        surface_key: the surface under attack.
        capability_id: the capability probing the surface.
        context: the :class:`SurfaceContext` the plan runs under.
        vectors: applicable attack vectors.
        aggression: bounded aggression tier.
        strategy: strategy label.
        baseline_payload: the differential baseline.
        payloads: bounded payload set (from the platform capability catalog).
        mutations: bounded controlled request mutations.
        steps: the strategy ladder.
        timeout_seconds: per-request timeout ceiling.
        retry_limit: bounded retries.
        probe_spec: serialized concrete probe reference (capability-built).
        created_at: UTC ISO-8601 creation stamp.

    """

    plan_id: str = field(default_factory=generate_id)
    surface_key: str = ""
    capability_id: str = ""
    context: SurfaceContext = field(default_factory=SurfaceContext)
    vectors: tuple[AttackVector, ...] = ()
    aggression: AggressionLevel = AggressionLevel.MEDIUM
    strategy: str = "baseline-probe-differential-escalate-verify"
    baseline_payload: str = ""
    payloads: tuple[str, ...] = ()
    mutations: tuple[dict[str, Any], ...] = ()
    steps: tuple[ProbeStep, ...] = ProbeStep.ladder()
    timeout_seconds: float = 15.0
    retry_limit: int = 2
    probe_spec: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow_iso)

    def __post_init__(self) -> None:
        # Defense in depth: the plan itself enforces its aggression profile's
        # hard budgets regardless of how it was constructed, so no caller can
        # accidentally hand an unbounded payload/mutation set to a tool.
        profile = profile_for(self.aggression)
        if len(self.payloads) > profile.payload_budget:
            self.payloads = self.payloads[: profile.payload_budget]
        if len(self.mutations) > profile.mutation_depth:
            self.mutations = self.mutations[: profile.mutation_depth]

    def profile(self) -> AggressionProfile:
        """Return the aggression profile backing this plan."""
        return profile_for(self.aggression)

    def escalated(self) -> AttackProbePlan:
        """Return a copy escalated one bounded tier (ceiling ``MAXIMUM``)."""
        next_level = self.aggression.escalate()
        profile = profile_for(next_level)
        return AttackProbePlan(
            plan_id=generate_id(),
            surface_key=self.surface_key,
            capability_id=self.capability_id,
            context=self.context,
            vectors=self.vectors,
            aggression=next_level,
            strategy=f"{self.strategy};escalated-to-{next_level.value}",
            baseline_payload=self.baseline_payload,
            payloads=bounded_payloads(self.payloads, next_level),
            mutations=bounded_mutations(self.mutations, next_level),
            steps=self.steps,
            timeout_seconds=profile.timeout_seconds,
            retry_limit=profile.retry_limit,
            probe_spec=self.probe_spec,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe mapping."""
        return {
            "plan_id": self.plan_id,
            "surface_key": self.surface_key,
            "capability_id": self.capability_id,
            "context": self.context.to_dict(),
            "vectors": [vector.value for vector in self.vectors],
            "aggression": self.aggression.value,
            "strategy": self.strategy,
            "baseline_payload": self.baseline_payload,
            "payload_count": len(self.payloads),
            "mutation_count": len(self.mutations),
            "steps": [step.value for step in self.steps],
            "timeout_seconds": self.timeout_seconds,
            "retry_limit": self.retry_limit,
            "probe_spec": self.probe_spec,
            "profile": self.profile().to_dict(),
            "created_at": self.created_at,
        }


__all__ = [
    "AggressionProfile",
    "AttackProbePlan",
    "ProbeStep",
    "bounded_mutations",
    "bounded_payloads",
    "profile_for",
]
