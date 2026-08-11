# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Hypothesis Engine.

Sprint 026. The Hypothesis Engine turns observations, technologies, endpoint
behavior, history, relationships and known-vulnerability knowledge into
conjectures to validate. Hypotheses are never conclusions: they carry supporting
and contradicting observations, required evidence, and validation/proof
strategies. Novel behavior that matches no known signature enters as
``UNKNOWN_BEHAVIOR``/``NOVEL_VARIANT`` so a finding never requires a CVE first.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunterx.domain.target_intelligence.enums import (
    HypothesisStatus,
    HypothesisType,
    ObservationType,
)
from hunterx.domain.target_intelligence.models import (
    Hypothesis,
    IntelligenceAsset,
    TargetIntelligenceState,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Known CVE-bearing technology map used by the knowledge-driven rule. This is
#: a *stand-in* for the vulnerability knowledge base; the platform replaces it
#: with live CVE data when available. Keys are lowercase technology names.
_KNOWN_VULNERABLE_TECH: dict[str, tuple[str, ...]] = {
    "apache log4j": ("log4shell", "CVE-2021-44228"),
    "apache struts": ("s2-045", "CVE-2017-5638"),
    "apache tomcat": ("ghostcat", "CVE-2020-1938"),
    "wordpress": ("plugin/theme vulnerabilities", "CVE-2020-xxxx"),
    "drupal": ("drupalgeddon", "CVE-2018-7600"),
    "joomla": ("joomla core rce", "CVE-2015-8562"),
    "jenkins": ("unauthenticated rce", "CVE-2024-23897"),
    "spring": ("spring4shell", "CVE-2022-22965"),
    "fastjson": ("fastjson rce", "CVE-2022-25845"),
    "phpunit": ("phpunit rce", "CVE-2017-9841"),
}

#: Endpoint kinds that accept parameters and are injection candidates.
_PARAM_ENDPOINT_KINDS = {
    EntityKind.URL.value,
    EntityKind.API_ENDPOINT.value,
    EntityKind.GRAPHQL_ENDPOINT.value,
    EntityKind.WEBSOCKET_ENDPOINT.value,
}


class HypothesisEngine:
    """Generate and refine hypotheses from the intelligence state.

    Rules are pluggable: subclass and override :meth:`rules` to add
    capability/knowledge-driven hypothesis generators without touching the
    engine core.
    """

    def generate(self, state: TargetIntelligenceState) -> list[Hypothesis]:
        """Generate fresh hypotheses for a target state.

        The engine is idempotent by statement: identical conjectures collapse
        onto the same :class:`Hypothesis` identity per target.
        """
        hypotheses: list[Hypothesis] = []
        seen: set[tuple[str, str]] = set()

        def add(
            *,
            asset_key: str,
            category: HypothesisType,
            statement: str,
            supporting: Sequence[str] = (),
            confidence: float,
            priority: float,
            validation_strategy: str,
            proof_strategy: str = "",
        ) -> None:
            marker = (asset_key, statement)
            if marker in seen:
                return
            seen.add(marker)
            hypotheses.append(
                Hypothesis(
                    hypothesis_id=generate_id(),
                    target_id=state.target.target_id,
                    mission_id=state.target.mission_id,
                    asset_key=asset_key,
                    category=category,
                    statement=statement,
                    supporting_observations=tuple(supporting),
                    validation_strategy=validation_strategy,
                    proof_strategy=proof_strategy,
                    confidence=confidence,
                    priority=priority,
                    status=HypothesisStatus.PROPOSED,
                    created_at=utcnow_iso(),
                    updated_at=utcnow_iso(),
                    provenance={"source": "hypothesis-engine", "version": "1.0.0"},
                )
            )

        for rule in self.rules():
            rule.apply(state=state, add=add, engine=self)

        # Conflicts become validation hypotheses (never auto-resolved).
        for conflict in state.conflicts:
            if conflict.state.value == "open":
                add(
                    asset_key=conflict.asset_key,
                    category=HypothesisType.UNKNOWN_BEHAVIOR,
                    statement=(
                        f"Conflicting results from {' and '.join(conflict.tools)} "
                        f"for {conflict.capability.value} on {conflict.asset_key} require "
                        "higher-quality evidence collection."
                    ),
                    supporting=[o.get("observation_id", "") for o in conflict.observations if isinstance(o, dict)],
                    confidence=0.6,
                    priority=0.8,
                    validation_strategy="corroboration",
                    proof_strategy="differential-proof",
                )

        return sorted(hypotheses, key=lambda h: (-h.priority, h.confidence))

    def refine(self, hypothesis: Hypothesis, state: TargetIntelligenceState) -> Hypothesis:
        """Update a hypothesis with the latest supporting/contradicting evidence.

        Returns a new hypothesis with an updated status derived from the balance
        of supporting vs contradicting observations.
        """
        supporting = hypothesis.supporting_observations
        contradicting = hypothesis.contradicting_observations
        if contradicting and not supporting:
            status = HypothesisStatus.CONTRADICTED
        elif supporting and len(supporting) >= 2:
            status = HypothesisStatus.SUPPORTED
        else:
            status = hypothesis.status
        import dataclasses

        return dataclasses.replace(
            hypothesis,
            status=status,
            updated_at=utcnow_iso(),
        )

    # -- rules ---------------------------------------------------------------

    def rules(self) -> list[HypothesisRule]:
        """Return the active hypothesis rules (ordered)."""
        return [
            TechnologyVulnerabilityRule(),
            ParameterInjectionRule(),
            AuthenticationRule(),
            AuthorizationRule(),
            GraphQLRule(),
            CloudExposureRule(),
            SecretExposureRule(),
            JavascriptRouteRule(),
            UnknownBehaviorRule(),
        ]


class HypothesisRule:
    """Base class for hypothesis rules."""

    def apply(
        self,
        *,
        state: TargetIntelligenceState,
        add: Any,
        engine: HypothesisEngine,
    ) -> None:  # pragma: no cover - abstract
        """Apply the rule to a target state, emitting hypotheses via ``add``."""
        raise NotImplementedError


def _kind(asset: IntelligenceAsset) -> str:
    return asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)


def _observation(state: TargetIntelligenceState, asset_key: str, observation_type: str) -> bool:
    return bool(state.target.intelligence_state.get(f"{asset_key}:{observation_type}"))


class TechnologyVulnerabilityRule(HypothesisRule):
    """Known-vulnerability hypotheses from fingerprinted technology."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            kind = _kind(asset)
            if kind not in (EntityKind.TECHNOLOGY.value, EntityKind.SERVICE.value, EntityKind.URL.value):
                continue
            for tech_name, facts in _KNOWN_VULNERABLE_TECH.items():
                haystack = f"{asset.name} {asset.label} {asset.properties}".lower()
                if tech_name not in haystack:
                    continue
                description, cve = facts
                add(
                    asset_key=asset.key,
                    category=HypothesisType.KNOWN_VULNERABILITY,
                    statement=f"{asset.key} appears to run {tech_name}; verify {cve} ({description}).",
                    supporting=(),
                    confidence=0.7,
                    priority=0.9,
                    validation_strategy=f"fingerprint-{tech_name}",
                    proof_strategy="version-proof",
                )


class ParameterInjectionRule(HypothesisRule):
    """Injection/XSS/SSRF hypotheses for parameterized endpoints."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            kind = _kind(asset)
            if kind not in _PARAM_ENDPOINT_KINDS:
                continue
            params = asset.properties.get("parameters") or ()
            has_params = bool(params)
            if kind == EntityKind.GRAPHQL_ENDPOINT.value:
                add(
                    asset_key=asset.key,
                    category=HypothesisType.GRAPHQL_SECURITY,
                    statement=f"GraphQL endpoint {asset.key} may expose unsafe queries/introspection.",
                    supporting=(),
                    confidence=0.6,
                    priority=0.8,
                    validation_strategy="graphql-security",
                    proof_strategy="request-response-proof",
                )
                continue
            if has_params or _observation(state, asset.key, ObservationType.PARAMETER.value):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.INJECTION,
                    statement=f"{asset.key} accepts parameters and may be injectable (SQLi/OS/NoSQL).",
                    supporting=(),
                    confidence=0.5,
                    priority=0.8,
                    validation_strategy="sql-injection-testing",
                    proof_strategy="differential-proof",
                )
                add(
                    asset_key=asset.key,
                    category=HypothesisType.XSS,
                    statement=f"{asset.key} reflects parameters and may store/reflect XSS.",
                    supporting=(),
                    confidence=0.4,
                    priority=0.7,
                    validation_strategy="xss-testing",
                    proof_strategy="reflection-proof",
                )
            if asset.properties.get("fetches_url") or asset.properties.get("redirect"):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.SSRF,
                    statement=f"{asset.key} accepts URL input and may be SSRF-prone.",
                    supporting=(),
                    confidence=0.5,
                    priority=0.8,
                    validation_strategy="ssrf-testing",
                    proof_strategy="controlled-callback-proof",
                )


class AuthenticationRule(HypothesisRule):
    """Authentication-issue hypotheses from auth surfaces."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            kind = _kind(asset)
            if kind in (EntityKind.AUTH_SURFACE.value, EntityKind.AUTH_ENDPOINT.value):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.AUTHENTICATION_ISSUE,
                    statement=f"Authentication surface {asset.key} may allow bypass/weak credential handling.",
                    supporting=(),
                    confidence=0.5,
                    priority=0.75,
                    validation_strategy="authentication-analysis",
                    proof_strategy="authentication-proof",
                )


class AuthorizationRule(HypothesisRule):
    """Authorization-issue hypotheses from admin/authorization surfaces."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            kind = _kind(asset)
            if kind in (EntityKind.ADMIN_SURFACE.value, EntityKind.AUTHORIZATION_ENDPOINT.value):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.AUTHORIZATION_ISSUE,
                    statement=f"Authorization boundary {asset.key} may be bypassable (IDOR/broken access control).",
                    supporting=(),
                    confidence=0.5,
                    priority=0.8,
                    validation_strategy="authorization-analysis",
                    proof_strategy="access-control-proof",
                )
                add(
                    asset_key=asset.key,
                    category=HypothesisType.IDOR,
                    statement=f"{asset.key} may expose object-level authorization flaws (IDOR).",
                    supporting=(),
                    confidence=0.5,
                    priority=0.75,
                    validation_strategy="object-level-authorization-testing",
                    proof_strategy="access-control-proof",
                )


class GraphQLRule(HypothesisRule):
    """GraphQL-security hypotheses for discovered GraphQL endpoints."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            if _kind(asset) != EntityKind.GRAPHQL_ENDPOINT.value:
                continue
            add(
                asset_key=asset.key,
                category=HypothesisType.GRAPHQL_SECURITY,
                statement=f"GraphQL endpoint {asset.key} may expose introspection or unsafe resolvers.",
                supporting=(),
                confidence=0.6,
                priority=0.8,
                validation_strategy="graphql-security",
                proof_strategy="request-response-proof",
            )


class CloudExposureRule(HypothesisRule):
    """Cloud-exposure hypotheses from cloud resources."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            kind = _kind(asset)
            if kind in (
                EntityKind.CLOUD_RESOURCE.value,
                EntityKind.STORAGE_RESOURCE.value,
                EntityKind.COMPUTE_RESOURCE.value,
                EntityKind.KUBERNETES_RESOURCE.value,
                EntityKind.CLOUD_ENDPOINT.value,
            ) and (asset.properties.get("public") or asset.properties.get("internet_facing")):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.CLOUD_EXPOSURE,
                    statement=f"Cloud resource {asset.key} is internet-facing and may be misconfigured.",
                    supporting=(),
                    confidence=0.6,
                    priority=0.8,
                    validation_strategy="cloud-configuration-review",
                    proof_strategy="cloud-configuration-proof",
                )


class SecretExposureRule(HypothesisRule):
    """Secret-exposure hypotheses from secret observations/repos."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            if _kind(asset) != EntityKind.REPOSITORY.value:
                continue
            if asset.properties.get("has_secrets"):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.SECRET_EXPOSURE,
                    statement=f"Repository {asset.key} may leak secrets in its history or files.",
                    supporting=(),
                    confidence=0.7,
                    priority=0.85,
                    validation_strategy="secret-scanning",
                    proof_strategy="dependency-proof",
                )


class JavascriptRouteRule(HypothesisRule):
    """API/endpoint hypotheses from JavaScript-referenced routes."""

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            if _kind(asset) != EntityKind.JAVASCRIPT.value:
                continue
            refs = asset.properties.get("endpoints") or asset.properties.get("routes") or ()
            if refs:
                add(
                    asset_key=asset.key,
                    category=HypothesisType.API_SECURITY,
                    statement=f"JavaScript {asset.key} references {len(refs)} endpoints worth mapping for API exposure.",
                    supporting=(),
                    confidence=0.6,
                    priority=0.7,
                    validation_strategy="api-mapping",
                    proof_strategy="request-response-proof",
                )


class UnknownBehaviorRule(HypothesisRule):
    """Novel/unknown behavior hypotheses for assets with no matching signature.

    This rule guarantees the pipeline never requires a CVE or an existing
    signature before creating a hypothesis.
    """

    def apply(self, *, state: TargetIntelligenceState, add: Any, engine: HypothesisEngine) -> None:
        for asset in state.assets:
            behavior = asset.properties.get("behavior") or asset.properties.get("anomaly")
            if behavior:
                add(
                    asset_key=asset.key,
                    category=HypothesisType.NOVEL_VARIANT,
                    statement=(
                        f"{asset.key} exhibits unexplained behavior ({behavior}); "
                        "observe, experiment, compare and refine before concluding."
                    ),
                    supporting=(),
                    confidence=0.4,
                    priority=0.6,
                    validation_strategy="behavioral-observation",
                    proof_strategy="differential-proof",
                )
        # Endpoints whose purpose is unknown but that accept input.
        for asset in state.assets:
            if _kind(asset) in _PARAM_ENDPOINT_KINDS and not asset.properties.get("purpose"):
                add(
                    asset_key=asset.key,
                    category=HypothesisType.UNKNOWN_BEHAVIOR,
                    statement=f"The purpose of {asset.key} is unknown; map its behavior before testing.",
                    supporting=(),
                    confidence=0.4,
                    priority=0.5,
                    validation_strategy="endpoint-behavior-mapping",
                    proof_strategy="",
                )


__all__ = [
    "Hypothesis",
    "HypothesisEngine",
    "HypothesisRule",
    "HypothesisStatus",
    "HypothesisType",
]
