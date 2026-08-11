# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Authentication intelligence correlation and conflict detection.

Correlates authentication observations from multiple sources into a single
canonical set, merging corroborating facts and surfacing conflicts. The
correlator never silently discards an observation: evidence that disagrees
(e.g. the same cookie reported with different security attributes) is reported
as :class:`AuthConflict` records with full provenance, and every out-of-scope
or below-threshold observation is counted rather than dropped silently.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from hunterx.domain.auth.confidence import AuthConfidenceEngine, AuthConfidencePolicy
from hunterx.domain.auth.models import AuthConflict, AuthEvidence
from hunterx.domain.auth.scope import AuthScopeEnforcer, AuthScopePolicy
from hunterx.domain.auth.validator import AuthValidator


@dataclass(frozen=True, slots=True)
class AuthCorrelationResult:
    """The outcome of correlating a set of auth observations.

    Attributes:
        records: canonical, merged authentication observations.
        conflicts: observations that disagreed across sources.
        scoped_out: observations removed by scope enforcement.
        dropped: observations removed by confidence/threshold policies.
        merged: number of observation groups that carried corroboration.

    """

    records: tuple[Any, ...] = ()
    conflicts: tuple[AuthConflict, ...] = ()
    scoped_out: int = 0
    dropped: int = 0
    merged: int = 0


class AuthCorrelator:
    """Correlate authentication observations into a canonical set.

    Observations sharing a canonical key are merged: evidence folded and
    confidence raised by corroboration. Distinct values within a group produce
    an :class:`AuthConflict` rather than a silent selection.
    """

    def __init__(
        self,
        *,
        scope: AuthScopePolicy | None = None,
        confidence: AuthConfidencePolicy | None = None,
        min_confidence: float = 0.0,
    ) -> None:
        self._scope = scope or AuthScopePolicy()
        self._confidence_policy = confidence or AuthConfidencePolicy()
        self._confidence = AuthConfidenceEngine(self._confidence_policy)
        self._enforcer = AuthScopeEnforcer(self._scope)
        self._validator = AuthValidator()
        self._min_confidence = min_confidence

    def correlate(
        self,
        observations: Iterable[Any],
        *,
        min_confidence: float | None = None,
    ) -> AuthCorrelationResult:
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
        conflicts: list[AuthConflict] = []
        merged = 0
        for _key, group in grouped.items():
            if len(group) > 1:
                merged += 1
            canonical, conflict = self._merge_group(group)
            records.append(canonical)
            if conflict is not None:
                conflicts.append(conflict)

        records.sort(key=lambda obs: (str(getattr(obs, "origin", "")), str(getattr(obs, "name", ""))))
        return AuthCorrelationResult(
            records=tuple(records),
            conflicts=tuple(_dedupe_conflicts(conflicts)),
            scoped_out=scoped_out,
            dropped=dropped,
            merged=merged,
        )

    # -- group merging ------------------------------------------------------

    def _merge_group(self, group: Sequence[Any]) -> tuple[Any, AuthConflict | None]:
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
            conflict = AuthConflict(
                subject=_key_of(representative),
                subject_type=_subject_type(representative),
                conflict_type="identity",
                observations=tuple(_record_payload(observation) for observation in group),
                selected=_value_of(representative),
                selected_source=str(getattr(representative, "source", "")),
                reason="conflicting authentication evidence across sources",
                confidence=self._confidence.observation_confidence(representative),
            )
        return merged, conflict


def _key_of(observation: Any) -> str:
    key = getattr(observation, "key", None)
    return key() if callable(key) else str(observation)


def _value_of(observation: Any) -> str:
    """Return the scalar value that defines an observation's identity state."""
    return f"{_kind_value(observation, 'kind')}|{_kind_value(observation, 'scheme_type')}|{_stability_payload(observation)}"


def _kind_value(observation: Any, name: str) -> str:
    """Coerce an enum-or-string attribute to its string form."""
    value = getattr(observation, name, None)
    enum_value = getattr(value, "value", None)
    return str(enum_value) if enum_value is not None else str(value)


def _stability_payload(observation: Any) -> str:
    parts: list[str] = []
    for name in ("name", "value", "allow_origin", "samesite", "secure", "httponly", "storage_type", "issuer"):
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


def _fold_evidence(group: Sequence[Any]) -> tuple[AuthEvidence, ...]:
    seen: set[tuple[str, str]] = set()
    evidence: list[AuthEvidence] = []
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
        "AuthSurfaceObservation": "surface",
        "AuthEndpointObservation": "endpoint",
        "AuthFlowObservation": "flow",
        "IdPObservation": "identity-provider",
        "OAuthObservation": "oauth",
        "OIDCObservation": "oidc",
        "SAMLIndicatorObservation": "saml",
        "JWTIndicatorObservation": "jwt",
        "AuthSchemeObservation": "scheme",
        "AuthCookieObservation": "cookie",
        "TokenStorageObservation": "token-storage",
        "CSRFObservation": "csrf",
        "CORSObservation": "cors",
        "MFAObservation": "mfa",
        "WebAuthnObservation": "webauthn",
        "RoleObservation": "role",
        "ScopeObservation": "scope",
        "PermissionObservation": "permission",
        "TenantObservation": "tenant",
        "AuthObservation": "observation",
    }
    return mapping.get(type(observation).__name__, "observation")


def _dedupe_conflicts(conflicts: Iterable[AuthConflict]) -> list[AuthConflict]:
    seen: set[str] = set()
    unique: list[AuthConflict] = []
    for conflict in conflicts:
        key = f"{conflict.subject}|{conflict.selected}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(conflict)
    return unique
