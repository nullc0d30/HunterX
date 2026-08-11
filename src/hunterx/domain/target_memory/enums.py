# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Target Memory & Campaign Intelligence — canonical enums.

Sprint 030. Pure, storage-agnostic value categories for the historical
intelligence layer: observation freshness, memory state classification, change
significance, diff change kinds, coverage gap taxonomy, hypothesis outcomes,
campaign lifecycle, recurrence kinds and revalidation priority.

The vocabulary keeps *current state*, *historical state* and *derived
intelligence* strictly separated. Historical evidence is never silently
overwritten: contradictions and stale observations are preserved and
classified, never discarded.
"""

from __future__ import annotations

from enum import StrEnum


class FreshnessState(StrEnum):
    """Classification of an observation against its freshness policy.

    ``FRESH`` means within the observation-type freshness window;
    ``AGING`` means approaching the window; ``STALE`` means the window elapsed
    and the value should be revalidated before reuse; ``EXPIRED`` means the
    value is no longer trustworthy; ``UNKNOWN`` means no policy applies.
    """

    FRESH = "fresh"
    AGING = "aging"
    STALE = "stale"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class MemoryObservationState(StrEnum):
    """Current-state classification of a memory observation.

    Mirrors the Sprint 030 smart-recon vocabulary: a known value stays
    ``KNOWN_CURRENT`` while fresh; it becomes ``KNOWN_STALE`` when the
    freshness window elapses; ``KNOWN_CHANGED`` when a newer observation
    contradicts it; ``CONTRADICTED`` when sources disagree and no resolution
    exists; ``NEEDS_REVALIDATION`` when it must be re-collected before reuse;
    ``UNKNOWN`` when nothing is recorded.
    """

    KNOWN_CURRENT = "known_current"
    KNOWN_STALE = "known_stale"
    KNOWN_CHANGED = "known_changed"
    UNKNOWN = "unknown"
    CONTRADICTED = "contradicted"
    NEEDS_REVALIDATION = "needs_revalidation"


class ChangeSignificance(StrEnum):
    """Priority class of a detected target change.

    Not every change deserves equal attention. Severity stays evidence-backed:
    a change is never classified higher than the confidence of the evidence
    that produced it.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return the escalation rank used for ordering."""
        return {
            ChangeSignificance.INFORMATIONAL: 0,
            ChangeSignificance.LOW: 1,
            ChangeSignificance.MEDIUM: 2,
            ChangeSignificance.HIGH: 3,
            ChangeSignificance.CRITICAL: 4,
        }[self]


class DiffChangeKind(StrEnum):
    """Kind of a single change produced by the :class:`TargetDiffEngine`.

    ``ADDED``/``REMOVED`` cover the base set; ``CHANGED`` marks a value
    mutation; ``UNCHANGED`` is recorded for completeness; ``REAPPEARED``
    tracks an observation that returned after removal;
    ``DISAPPEARED`` tracks an observation that vanished; ``REOPENED`` and
    ``REMEDIATED`` describe finding lifecycle transitions across snapshots.
    """

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    REAPPEARED = "reappeared"
    DISAPPEARED = "disappeared"
    REOPENED = "reopened"
    REMEDIATED = "remediated"


class CampaignStatus(StrEnum):
    """Lifecycle state of a campaign."""

    PLANNED = "planned"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class CoverageGapKind(StrEnum):
    """Canonical taxonomy of coverage gaps.

    Each gap maps to a concrete, actionable deficiency — never a vague "more
    testing needed".
    """

    DISCOVERED_UNTESTED = "discovered_untested"
    UNTESTED_PARAMETERS = "untested_parameters"
    UNTESTED_TECHNOLOGY = "untested_technology"
    UNVALIDATED_CONFIG = "unvalidated_config"
    UNTESTED_AUTH = "untested_auth"
    NEW_ASSET = "new_asset"
    STALE_OBSERVATION = "stale_observation"
    BLOCKED = "blocked"


class HypothesisOutcome(StrEnum):
    """Historical outcome of a hypothesis.

    ``FAILED`` means validation produced no evidence (useless to re-test);
    ``SUCCEEDED`` means the hypothesis was validated/proven; ``INCONCLUSIVE``
    means the outcome was indeterminate.
    """

    FAILED = "failed"
    SUCCEEDED = "succeeded"
    INCONCLUSIVE = "inconclusive"


class RecurrenceKind(StrEnum):
    """Classification of a finding recurrence.

    ``SAME_LOCATION`` means the exact affected location regressed;
    ``NEW_LOCATION`` means the same root-cause family appeared at a new
    location (potential regression); ``ROOT_CAUSE_REGRESSION`` means a
    previously remediated root cause returned.
    """

    SAME_LOCATION = "same_location"
    NEW_LOCATION = "new_location"
    ROOT_CAUSE_REGRESSION = "root_cause_regression"


class MemoryValidity(StrEnum):
    """Whether a memory item is still trustworthy.

    ``VALID`` means the recorded value remains authoritative; ``SUPERSEDED``
    means a newer observation corrected it; ``INVALIDATED`` means a
    contradiction or validation disproved it.
    """

    VALID = "valid"
    SUPERSEDED = "superseded"
    INVALIDATED = "invalidated"


class RiskLevel(StrEnum):
    """Historical target risk level.

    Risk is recorded per campaign/mission and never overwritten: each entry
    is a point-in-time assessment.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return the ordering rank of the risk level."""
        return {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }[self]


class RevalidationPriority(StrEnum):
    """Priority of a revalidation item."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        """Return the ordering rank of the priority."""
        return {
            RevalidationPriority.LOW: 0,
            RevalidationPriority.MEDIUM: 1,
            RevalidationPriority.HIGH: 2,
        }[self]


class MemoryContradictionState(StrEnum):
    """Lifecycle state of a preserved memory contradiction."""

    OPEN = "open"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


__all__ = [
    "CampaignStatus",
    "ChangeSignificance",
    "CoverageGapKind",
    "DiffChangeKind",
    "FreshnessState",
    "HypothesisOutcome",
    "MemoryContradictionState",
    "MemoryObservationState",
    "MemoryValidity",
    "RecurrenceKind",
    "RevalidationPriority",
    "RiskLevel",
]
