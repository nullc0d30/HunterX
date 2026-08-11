# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud intelligence correlation.

Groups raw observations into canonical records by their deduplication key,
merges corroborating evidence, resolves conflicts deterministically and drops
out-of-scope or low-confidence observations. Pure; no I/O.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

from hunterx.domain.cloud.confidence import CloudConfidenceEngine, CloudConfidencePolicy
from hunterx.domain.cloud.conflicts import CloudConflictResolver
from hunterx.domain.cloud.models import CloudConflict
from hunterx.domain.cloud.scope import CloudScopeEnforcer, CloudScopePolicy
from hunterx.domain.cloud.validator import CloudValidator


@dataclass(frozen=True, slots=True)
class CloudCorrelationResult:
    """The outcome of correlating a set of cloud observations.

    Attributes:
        records: canonical correlated records.
        conflicts: recorded disagreements.
        scoped_out: observations dropped by scope.
        dropped: observations dropped by confidence.
        merged: number of merged groups.

    """

    records: tuple[Any, ...] = ()
    conflicts: tuple[CloudConflict, ...] = ()
    scoped_out: int = 0
    dropped: int = 0
    merged: int = 0


class CloudCorrelator:
    """Correlate cloud observations into canonical records."""

    def __init__(
        self,
        *,
        scope: CloudScopePolicy | None = None,
        confidence: CloudConfidencePolicy | None = None,
        min_confidence: float = 0.0,
    ) -> None:
        self._scope_enforcer = CloudScopeEnforcer(scope or CloudScopePolicy())
        self._confidence = CloudConfidenceEngine(confidence or CloudConfidencePolicy())
        self._conflicts = CloudConflictResolver()
        self._validator = CloudValidator()
        self._default_min_confidence = min_confidence

    @property
    def scope(self) -> CloudScopeEnforcer:
        """Return the scope enforcer used by this correlator."""
        return self._scope_enforcer

    def correlate(
        self,
        observations: Sequence[Any],
        *,
        min_confidence: float | None = None,
    ) -> CloudCorrelationResult:
        """Correlate ``observations`` into canonical records.

        Args:
            observations: raw observations to correlate.
            min_confidence: minimum confidence threshold (overrides the
                correlator default).

        Returns:
            The correlation result with canonical records and conflicts.

        """
        effective_min = self._default_min_confidence if min_confidence is None else min_confidence
        groups: dict[str, list[Any]] = {}
        scoped_out = 0
        dropped = 0
        for observation in observations:
            if not self._scope_enforcer.allows_observation(observation).allowed:
                scoped_out += 1
                continue
            if self._confidence.observation_confidence(observation) < effective_min:
                dropped += 1
                continue
            groups.setdefault(_key_of(observation), []).append(observation)

        records: list[Any] = []
        conflicts: list[CloudConflict] = []
        merged = 0
        for key, group in groups.items():
            if len(group) > 1:
                merged += 1
            record, conflict = self._merge_group(key, group)
            records.append(record)
            if conflict is not None:
                conflicts.append(conflict)

        records.sort(key=_sort_key)
        return CloudCorrelationResult(
            records=tuple(records),
            conflicts=tuple(_dedupe_conflicts(conflicts)),
            scoped_out=scoped_out,
            dropped=dropped,
            merged=merged,
        )

    def _merge_group(self, key: str, group: list[Any]) -> tuple[Any, CloudConflict | None]:
        """Merge one group into a canonical record plus any conflict."""
        validated = [obs for obs in group if self._validator.validate(obs).valid]
        if not validated:
            validated = group
        representative = max(validated, key=self._confidence.observation_confidence)
        conflict = self._conflicts.resolve(
            validated,
            subject=key,
            subject_type=_subject_type(representative),
            conflict_type="identity",
        )
        merged = replace(
            representative,
            evidence=_fold_evidence(group),
            confidence=self._confidence.merged_confidence(group, conflicted=conflict.conflict is not None),
        )
        return merged, conflict.conflict


def _key_of(observation: Any) -> str:
    """Return the deduplication key of an observation."""
    key = getattr(observation, "key", None)
    return key() if callable(key) else str(observation)


def _fold_evidence(group: list[Any]) -> tuple[Any, ...]:
    """Fold evidence fragments from a group, deduping by (type, value)."""
    seen: set[tuple[str, str]] = set()
    folded: list[Any] = []
    for observation in group:
        for item in getattr(observation, "evidence", ()) or ():
            key = (str(getattr(item, "evidence_type", "")), str(getattr(item, "value", "")))
            if key in seen:
                continue
            seen.add(key)
            folded.append(item)
    return tuple(folded)


def _sort_key(record: Any) -> tuple[str, str, str]:
    """Deterministic ordering for correlated records."""
    kind = type(record).__name__
    name = str(getattr(record, "name", "") or "")
    provider = str(getattr(record, "provider", "") or getattr(record, "saas_provider", "") or "")
    return (kind, provider, name)


def _subject_type(observation: Any) -> str:
    """Return the canonical subject label of an observation."""
    return _SUBJECT_TYPES.get(type(observation).__name__, "observation")


_SUBJECT_TYPES: dict[str, str] = {
    "CloudProviderObservation": "provider",
    "CloudServiceObservation": "service",
    "CloudResourceObservation": "resource",
    "CloudEndpointObservation": "endpoint",
    "CloudAccountObservation": "account",
    "CloudRegionObservation": "region",
    "CloudEnvironmentObservation": "environment",
    "CloudIdentityObservation": "identity",
    "CloudRoleObservation": "role",
    "CloudPermissionObservation": "permission",
    "CloudIntegrationObservation": "integration",
    "SaaSProviderObservation": "saas",
    "SaaSApplicationObservation": "saas-application",
    "SaaSIntegrationObservation": "saas-integration",
    "WebhookObservation": "webhook",
    "CloudDependencyObservation": "dependency",
    "StorageResourceObservation": "storage",
    "ComputeResourceObservation": "compute",
    "ContainerResourceObservation": "container",
    "KubernetesResourceObservation": "kubernetes",
    "DatabaseResourceObservation": "database",
    "MessageInfrastructureObservation": "message",
    "ApiGatewayResourceObservation": "gateway",
    "CdnResourceObservation": "cdn",
    "LoadBalancerResourceObservation": "load-balancer",
    "CiCdResourceObservation": "ci-cd",
    "SecretManagementObservation": "secret",
    "CloudExposureObservation": "exposure",
    "CloudObservation": "observation",
}


def _dedupe_conflicts(conflicts: Sequence[CloudConflict]) -> list[CloudConflict]:
    """Dedupe conflicts by subject + selected value, preserving order."""
    seen: set[str] = set()
    unique: list[CloudConflict] = []
    for conflict in conflicts:
        marker = f"{conflict.subject}|{conflict.selected}"
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(conflict)
    return unique
