# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authorization intelligence correlation and conflict detection.

Correlates authorization observations from multiple sources into a single
canonical set, merging corroborating facts and surfacing conflicts. The
correlator never silently discards an observation: evidence that disagrees
(e.g. the same permission reported with different action/resource values) is
reported as :class:`AuthorizationConflict` records with full provenance, and
every out-of-scope or below-threshold observation is counted rather than
dropped silently.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from hunterx.domain.authorization.confidence import (
    AuthorizationConfidenceEngine,
    AuthorizationConfidencePolicy,
)
from hunterx.domain.authorization.models import AuthorizationConflict, AuthzEvidence
from hunterx.domain.authorization.scope import (
    AuthorizationScopeEnforcer,
    AuthorizationScopePolicy,
)
from hunterx.domain.authorization.validator import AuthorizationValidator


@dataclass(frozen=True, slots=True)
class AuthorizationCorrelationResult:
    """The outcome of correlating a set of authorization observations.

    Attributes:
        records: canonical, merged authorization observations.
        conflicts: observations that disagreed across sources.
        scoped_out: observations removed by scope enforcement.
        dropped: observations removed by confidence/threshold policies.
        merged: number of observation groups that carried corroboration.

    """

    records: tuple[Any, ...] = ()
    conflicts: tuple[AuthorizationConflict, ...] = ()
    scoped_out: int = 0
    dropped: int = 0
    merged: int = 0


class AuthorizationCorrelator:
    """Correlate authorization observations into a canonical set.

    Observations sharing a canonical key are merged: evidence folded and
    confidence raised by corroboration. Distinct values within a group produce
    an :class:`AuthorizationConflict` rather than a silent selection.
    """

    def __init__(
        self,
        *,
        scope: AuthorizationScopePolicy | None = None,
        confidence: AuthorizationConfidencePolicy | None = None,
        min_confidence: float = 0.0,
    ) -> None:
        self._scope = scope or AuthorizationScopePolicy()
        self._confidence_policy = confidence or AuthorizationConfidencePolicy()
        self._confidence = AuthorizationConfidenceEngine(self._confidence_policy)
        self._enforcer = AuthorizationScopeEnforcer(self._scope)
        self._validator = AuthorizationValidator()
        self._min_confidence = min_confidence

    def correlate(
        self,
        observations: Iterable[Any],
        *,
        min_confidence: float | None = None,
    ) -> AuthorizationCorrelationResult:
        """Correlate observations into canonical records plus conflicts."""
        effective_min = self._min_confidence if min_confidence is None else min_confidence
        scoped_out = 0
        dropped = 0
        grouped: dict[str, list[Any]] = {}
        for observation in observations:
            if not self._enforcer.allows_observation(observation).allowed:
                scoped_out += 1
                continue
            if self._confidence.observation_confidence(observation) < effective_min:
                dropped += 1
                continue
            grouped.setdefault(_key_of(observation), []).append(observation)

        records: list[Any] = []
        conflicts: list[AuthorizationConflict] = []
        merged = 0
        for _key, group in grouped.items():
            if len(group) > 1:
                merged += 1
            canonical, conflict = self._merge_group(group)
            records.append(canonical)
            if conflict is not None:
                conflicts.append(conflict)

        records.sort(key=lambda obs: (str(getattr(obs, "origin", "")), str(getattr(obs, "name", ""))))
        return AuthorizationCorrelationResult(
            records=tuple(records),
            conflicts=tuple(_dedupe_conflicts(conflicts)),
            scoped_out=scoped_out,
            dropped=dropped,
            merged=merged,
        )

    # -- group merging ------------------------------------------------------

    def _merge_group(self, group: Sequence[Any]) -> tuple[Any, AuthorizationConflict | None]:
        representative = max(group, key=self._confidence.observation_confidence)
        values = {_value_of(observation) for observation in group}
        conflicted = len(values) > 1
        merged = replace(
            representative,
            evidence=_fold_evidence(group),
            confidence=self._confidence.merged_confidence(group, conflicted=conflicted),
        )
        conflict = None
        if conflicted:
            conflict = AuthorizationConflict(
                subject=_key_of(representative),
                subject_type=_subject_type(representative),
                conflict_type="identity",
                observations=tuple(_record_payload(observation) for observation in group),
                selected=_value_of(representative),
                selected_source=str(getattr(representative, "source", "")),
                reason="conflicting authorization evidence across sources",
                confidence=self._confidence.observation_confidence(representative),
            )
        return merged, conflict


def _key_of(observation: Any) -> str:
    key = getattr(observation, "key", None)
    return key() if callable(key) else str(observation)


def _value_of(observation: Any) -> str:
    """Return the scalar value that defines an observation's identity state."""
    return f"{_kind_value(observation, 'kind')}|{_kind_value(observation, 'model_kind')}|{_stability_payload(observation)}"


def _kind_value(observation: Any, name: str) -> str:
    """Coerce an enum-or-string attribute to its string form."""
    value = getattr(observation, name, None)
    enum_value = getattr(value, "value", None)
    return str(enum_value) if enum_value is not None else str(value)


def _stability_payload(observation: Any) -> str:
    parts: list[str] = []
    for name in (
        "name",
        "value",
        "action",
        "resource",
        "field",
        "identifier",
        "decision",
        "subject",
        "target",
        "role",
        "scope",
        "permission",
        "tenant",
        "check_type",
        "surface_kind",
        "function",
        "custom",
        "default",
        "model",
    ):
        value = getattr(observation, name, None)
        if value is None:
            continue
        parts.append(_stringify(value))
    return "|".join(parts)


def _stringify(value: Any) -> str:
    """Render a scalar, enum or iterable value as a stable string."""
    enum_value = getattr(value, "value", None)
    if enum_value is not None:
        return str(enum_value)
    if isinstance(value, (tuple, list)):
        return ",".join(str(item) for item in value)
    return str(value)


def _fold_evidence(group: Sequence[Any]) -> tuple[AuthzEvidence, ...]:
    seen: set[tuple[str, str]] = set()
    evidence: list[AuthzEvidence] = []
    for observation in group:
        for item in getattr(observation, "evidence", ()) or ():
            key = (str(getattr(item, "evidence_type", "")), str(getattr(item, "value", "")))
            if key in seen:
                continue
            seen.add(key)
            evidence.append(item)
    return tuple(evidence)


def _record_payload(observation: Any) -> dict[str, Any]:
    to_dict = getattr(observation, "to_dict", None)
    if callable(to_dict):
        payload = to_dict()
        if isinstance(payload, dict):
            return payload
    return {"origin": str(getattr(observation, "origin", "")), "kind": str(getattr(observation, "kind", ""))}


def _subject_type(observation: Any) -> str:
    mapping = {
        "AuthzSubjectObservation": "subject",
        "AuthzRoleObservation": "role",
        "AuthzGroupObservation": "group",
        "AuthzPermissionObservation": "permission",
        "AuthzScopeObservation": "scope",
        "AuthzClaimObservation": "claim",
        "AuthzPolicyObservation": "policy",
        "AuthzResourceObservation": "resource",
        "AuthzActionObservation": "action",
        "AuthzResourceIdentifierObservation": "identifier",
        "AuthzOwnershipObservation": "ownership",
        "AuthzTenantObservation": "tenant",
        "AuthzAdminSurfaceObservation": "admin-surface",
        "AuthzFunctionLevelObservation": "function-level",
        "AuthzObjectLevelObservation": "object-level",
        "AuthzFieldLevelObservation": "field-level",
        "AuthzFrontendObservation": "frontend",
        "AuthzBackendObservation": "backend",
        "AuthzApiCorrelationObservation": "api-correlation",
        "AuthzGraphQLObservation": "graphql",
        "AuthzWebSocketObservation": "websocket",
        "AuthzServiceObservation": "service",
        "AuthzDecisionObservation": "decision",
        "AuthzMassAssignmentObservation": "mass-assignment",
        "AuthzAccessControlObservation": "access-control",
        "AuthzObservation": "observation",
    }
    return mapping.get(type(observation).__name__, "observation")


def _dedupe_conflicts(conflicts: Iterable[AuthorizationConflict]) -> list[AuthorizationConflict]:
    seen: set[str] = set()
    unique: list[AuthorizationConflict] = []
    for conflict in conflicts:
        key = f"{conflict.subject}|{conflict.selected}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(conflict)
    return unique
