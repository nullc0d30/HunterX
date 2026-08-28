# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Capability × Surface × Context mapping.

The mapper turns a discovered surface into the set of security capabilities the
platform should schedule against it, conditioned on the observed context. The
*capability list* is always the live HunterX catalog (passed in at
construction, sourced from the vulnerability-capability registry and coverage
vocabulary); mapping rules that name capabilities absent from the catalog are
silently dropped, so this module can never invent capabilities.

Mapping is driven by declarative rules keyed by surface kind. Default rules
cover the generic surface taxonomy (authorization → object/API surfaces,
authentication → authentication surfaces, injection → input surfaces, SSRF →
URL-fetching surfaces, file vulnerabilities → file surfaces, client-side issues
→ client-side surfaces, workflow/state → access-control surfaces). New target
technologies add rules without changing core orchestration.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from hunterx.domain.attack_surface.enums import AuthContextState, SurfaceKind
from hunterx.domain.attack_surface.models import (
    CapabilityAssignment,
    SurfaceContext,
    SurfaceNode,
)
from hunterx.domain.attack_surface.registry import SurfaceKindRegistry

#: A context condition: whether a capability applies to a surface under a
#: (context, attributes) pair.
ContextPredicate = Callable[[SurfaceContext, dict[str, Any]], bool]

#: Base importance for well-known probeable capabilities (higher = more likely
#: to be scheduled first). Unknown capabilities default to ``0.5``.
_CAPABILITY_PRIORITY: dict[str, float] = {
    "sql-injection": 0.8,
    "nosql-injection": 0.75,
    "xss": 0.8,
    "ssti": 0.7,
    "command-injection": 0.7,
    "lfi": 0.75,
    "xxe": 0.7,
    "ssrf": 0.8,
    "open-redirect": 0.7,
    "idor": 0.8,
    "authentication": 0.8,
    "authorization": 0.8,
    "api-security": 0.7,
    "graphql-security": 0.75,
    "cloud-exposure": 0.7,
    "http-access-differential": 0.65,
    "cors-misconfiguration": 0.6,
    "security-misconfiguration": 0.6,
    "sensitive-information-exposure": 0.6,
    "known-vulnerable-component": 0.65,
    "dependency-vulnerability": 0.65,
}


def _fetch_surface(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` when the surface plausibly fetches remote URLs (SSRF surface)."""
    return context.fetch_hint


def _object_surface(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` when the surface exposes object identifiers (IDOR/BOLA surface)."""
    return context.object_hint


def _authenticated_object(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` for object surfaces reached with an established session."""
    return context.object_hint and context.auth_state in (
        AuthContextState.AUTHENTICATED,
        AuthContextState.MULTI_USER,
    )


def _multi_tenant(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` when the target is observed as multi-user/multi-tenant."""
    return context.multi_tenant


def _json_body(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` for JSON-bodied request surfaces (NoSQL-relevant)."""
    return context.content_type.lower() in ("application/json", "application/graphql")


def _graphql_tech(context: SurfaceContext, _attributes: dict[str, Any]) -> bool:
    """Return ``True`` when the application was observed running GraphQL."""
    return any("graphql" in tech.lower() for tech in context.technologies)


def _redirect_surface(context: SurfaceContext, attributes: dict[str, Any]) -> bool:
    """Return ``True`` when the surface is a redirect/forwarding behaviour."""
    return bool(context.fetch_hint or str(attributes.get("redirect") or "").lower() in ("true", "1", "yes"))


@dataclass(frozen=True, slots=True)
class CapabilityMappingRule:
    """A single ``Capability × SurfaceKind (+ Context)`` mapping rule.

    Attributes:
        kind: surface kind string the rule applies to.
        capability_id: capability id the rule schedules (must be in catalog).
        priority: mapping importance in ``[0, 1]``.
        applies: optional context predicate; ``None`` = always applies.
        rationale: explainable reason.

    """

    kind: str
    capability_id: str
    priority: float = 0.5
    applies: ContextPredicate | None = None
    rationale: str = ""


class CapabilityMapper:
    """Map discovered surfaces to applicable security capabilities.

    Args:
        catalog: the live capability id list (authoritative — rules naming
            capabilities outside it are dropped).
        registry: surface-kind registry used for default rules.
        rules: explicit rules; ``None`` builds the default rule set.
        capabilities_priority: capability id → importance overrides.

    """

    def __init__(
        self,
        catalog: Sequence[str],
        *,
        registry: SurfaceKindRegistry | None = None,
        rules: Sequence[CapabilityMappingRule] | None = None,
        capabilities_priority: dict[str, float] | None = None,
    ) -> None:
        self.catalog: set[str] = set(catalog)
        self._registry = registry if registry is not None else SurfaceKindRegistry()
        self._priority: dict[str, float] = dict(_CAPABILITY_PRIORITY)
        if capabilities_priority:
            self._priority.update(capabilities_priority)
        source_rules = rules if rules is not None else self._default_rules()
        self._rules_by_kind: dict[str, list[CapabilityMappingRule]] = {}
        for rule in source_rules:
            if rule.capability_id not in self.catalog:
                continue
            self._rules_by_kind.setdefault(rule.kind, []).append(rule)

    def _default_rules(self) -> list[CapabilityMappingRule]:
        """Build the default rule set from the registry hints + context rules."""
        rules: list[CapabilityMappingRule] = []
        for kind in self._registry.kinds():
            for capability_id in self._registry.default_capabilities(kind):
                rules.append(
                    CapabilityMappingRule(
                        kind=kind,
                        capability_id=capability_id,
                        priority=self._priority.get(capability_id, 0.5),
                        rationale=f"{capability_id} is a candidate for {kind} surfaces",
                    )
                )
        # Context-conditioned augmentations (fetch/object/authz/tenancy/graphql).
        for kind in (
            SurfaceKind.PARAMETER.value,
            SurfaceKind.JSON_FIELD.value,
            SurfaceKind.URL.value,
            SurfaceKind.ROUTE.value,
            SurfaceKind.ENDPOINT.value,
        ):
            rules.append(
                CapabilityMappingRule(
                    kind=kind,
                    capability_id="ssrf",
                    priority=0.85,
                    applies=_fetch_surface,
                    rationale=f"surface on {kind} plausibly fetches remote URLs",
                )
            )
        for kind in (
            SurfaceKind.ENDPOINT.value,
            SurfaceKind.API_ENDPOINT.value,
            SurfaceKind.GRAPHQL_OPERATION.value,
            SurfaceKind.OBJECT.value,
        ):
            rules.append(
                CapabilityMappingRule(
                    kind=kind,
                    capability_id="idor",
                    priority=0.85,
                    applies=_object_surface,
                    rationale=f"surface on {kind} exposes object identifiers",
                )
            )
            rules.append(
                CapabilityMappingRule(
                    kind=kind,
                    capability_id="authorization",
                    priority=0.85,
                    applies=_authenticated_object,
                    rationale=f"authenticated object surface on {kind} needs authorization checks",
                )
            )
        for kind in (SurfaceKind.API_ENDPOINT.value, SurfaceKind.OBJECT.value):
            rules.append(
                CapabilityMappingRule(
                    kind=kind,
                    capability_id="authorization",
                    priority=0.8,
                    applies=_multi_tenant,
                    rationale=f"multi-tenant {kind} surface needs authorization checks",
                )
            )
        rules.append(
            CapabilityMappingRule(
                kind=SurfaceKind.JSON_FIELD.value,
                capability_id="nosql-injection",
                priority=0.8,
                applies=_json_body,
                rationale="JSON body field on a JSON content-type surface",
            )
        )
        rules.append(
            CapabilityMappingRule(
                kind=SurfaceKind.ENDPOINT.value,
                capability_id="graphql-security",
                priority=0.8,
                applies=_graphql_tech,
                rationale="endpoint under a GraphQL technology application",
            )
        )
        rules.append(
            CapabilityMappingRule(
                kind=SurfaceKind.REDIRECT.value,
                capability_id="open-redirect",
                priority=0.8,
                applies=_redirect_surface,
                rationale="redirect surface may forward to attacker-chosen URLs",
            )
        )
        return rules

    def applicable_capabilities(self, surface: SurfaceNode) -> list[tuple[str, float, str]]:
        """Return ``(capability_id, priority, rationale)`` for ``surface``.

        Rules are evaluated against the surface's context and attributes;
        context-conditioned rules that do not match are excluded.
        """
        results: list[tuple[str, float, str]] = []
        for rule in self._rules_by_kind.get(surface.kind_value(), ()):
            if rule.applies is not None and not rule.applies(surface.context, surface.attributes):
                continue
            results.append((rule.capability_id, rule.priority, rule.rationale))
        # Deterministic, deduplicated ordering (highest importance first).
        unique: dict[str, tuple[float, str]] = {}
        for capability_id, priority, rationale in results:
            existing = unique.get(capability_id)
            if existing is None or priority > existing[0]:
                unique[capability_id] = (priority, rationale)
        return [(capability_id, priority, rationale) for capability_id, (priority, rationale) in sorted(
            unique.items(), key=lambda item: (-item[1][0], item[0])
        )]

    def map_for(self, surface: SurfaceNode) -> list[CapabilityAssignment]:
        """Return the applicable capability assignments for ``surface``."""
        assignments: list[CapabilityAssignment] = []
        for capability_id, priority, rationale in self.applicable_capabilities(surface):
            assignments.append(
                CapabilityAssignment(
                    surface_key=surface.key,
                    capability_id=capability_id,
                    context=surface.context,
                    applicable=True,
                    rationale=rationale,
                    priority=priority,
                )
            )
        return assignments

    def is_capability_supported(self, capability_id: str) -> bool:
        """Return ``True`` when ``capability_id`` is part of the live catalog."""
        return capability_id in self.catalog

    def to_dict(self) -> dict[str, Any]:
        """Serialize the mapper configuration to a JSON-safe mapping."""
        return {
            "catalog": sorted(self.catalog),
            "rules": sorted(
                {
                    (rule.kind, rule.capability_id): {
                        "kind": rule.kind,
                        "capability_id": rule.capability_id,
                        "priority": rule.priority,
                        "context_conditioned": rule.applies is not None,
                        "rationale": rule.rationale,
                    }
                    for rules in self._rules_by_kind.values()
                    for rule in rules
                }.values(),
                key=lambda entry: (entry["kind"], entry["capability_id"]),
            ),
        }


__all__ = ["CapabilityMapper", "CapabilityMappingRule"]
