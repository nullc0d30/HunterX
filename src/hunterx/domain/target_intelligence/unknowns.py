# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unknowns Engine.

Sprint 026. HunterX must explicitly represent uncertainty. The Unknowns Engine
walks the target's assets, observations and coverage matrix and produces
:class:`InformationGap` records — concrete questions that, if answered, advance
the intelligence state. Missing information is NEVER treated as negative
information.
"""

from __future__ import annotations

from collections.abc import Sequence

from hunterx.domain.target_intelligence.enums import (
    CoverageCapability,
    CoverageState,
    InformationGapCategory,
    UnknownCategory,
)
from hunterx.domain.target_intelligence.models import (
    InformationGap,
    IntelligenceAsset,
    TargetIntelligenceState,
)
from hunterx.domain.topology.enums import EntityKind
from hunterx.shared.ids import generate_id
from hunterx.shared.time import utcnow_iso

#: Tool families by capability used for candidate_tools on gaps. The engine
#: treats these as *candidates*; the Sprint 025 selector makes the final call.
_CANDIDATE_TOOLS: dict[CoverageCapability, tuple[str, ...]] = {
    CoverageCapability.ASSET_DISCOVERY: ("assetfinder", "theharvester", "bbot"),
    CoverageCapability.SUBDOMAIN_ENUMERATION: ("subfinder", "amass", "assetfinder"),
    CoverageCapability.PORT_DISCOVERY: ("naabu", "masscan", "nmap"),
    CoverageCapability.SERVICE_DETECTION: ("nmap", "httpx"),
    CoverageCapability.TECHNOLOGY_FINGERPRINT: ("httpx", "whatweb", "wappalyzer"),
    CoverageCapability.CONTENT_DISCOVERY: ("katana", "feroxbuster", "ffuf"),
    CoverageCapability.PARAMETER_DISCOVERY: ("arjun", "paramspider", "katana"),
    CoverageCapability.ENDPOINT_ENUMERATION: ("katana", "linkfinder", "waybackurls"),
    CoverageCapability.API_MAPPING: ("httpx", "katana", "arjun"),
    CoverageCapability.GRAPHQL_ENUMERATION: ("graphql-cop", "inql"),
    CoverageCapability.JAVASCRIPT_ANALYSIS: ("katana", "linkfinder", "retire.js"),
    CoverageCapability.DNS_ENUMERATION: ("dnsx", "dig"),
    CoverageCapability.CERTIFICATE_ENUMERATION: ("crt.sh", "certspotter"),
    CoverageCapability.AUTHENTICATION_ANALYSIS: ("httpx", "nuclei"),
    CoverageCapability.AUTHORIZATION_ANALYSIS: ("nuclei", "authanalyzer"),
    CoverageCapability.CLOUD_OWNERSHIP_MAPPING: ("shodan", "censys", "s3scanner"),
    CoverageCapability.VULNERABILITY_SCANNING: ("nuclei", "nikto"),
    CoverageCapability.SQL_INJECTION: ("sqlmap", "ghauri"),
    CoverageCapability.XSS: ("dalfox", "xsstrike"),
    CoverageCapability.SSRF: ("interactsh", "ffuf"),
    CoverageCapability.SSTI: ("sstimap", "tplmap"),
    CoverageCapability.XXE: ("xxeinjector", "interactsh"),
    CoverageCapability.LFI: ("ffuf", "nuclei"),
    CoverageCapability.RCE: ("nuclei", "nuclei-templates"),
    CoverageCapability.IDOR: ("authanalyzer", "nuclei"),
    CoverageCapability.API_SECURITY: ("nuclei", "mitmproxy"),
    CoverageCapability.GRAPHQL_SECURITY: ("graphql-cop", "inql"),
    CoverageCapability.SECRET_DETECTION: ("gitleaks", "trufflehog"),
    CoverageCapability.DEPENDENCY_CHECK: ("grype", "trivy", "osv-scanner"),
    CoverageCapability.PROOF_VALIDATION: ("sqlmap", "dalfox", "interactsh"),
    CoverageCapability.REPLAY: ("replay",),
}

#: Default importance per gap category; used when no context refines it.
_DEFAULT_IMPORTANCE: dict[InformationGapCategory, float] = {
    InformationGapCategory.ASSET_DISCOVERY: 0.7,
    InformationGapCategory.SUBDOMAIN_ENUMERATION: 0.8,
    InformationGapCategory.PORT_DISCOVERY: 0.8,
    InformationGapCategory.SERVICE_DETECTION: 0.8,
    InformationGapCategory.TECHNOLOGY_FINGERPRINT: 0.75,
    InformationGapCategory.CONTENT_DISCOVERY: 0.7,
    InformationGapCategory.PARAMETER_DISCOVERY: 0.8,
    InformationGapCategory.ENDPOINT_MAPPING: 0.8,
    InformationGapCategory.API_MAPPING: 0.85,
    InformationGapCategory.GRAPHQL_SCHEMA: 0.8,
    InformationGapCategory.JAVASCRIPT_ANALYSIS: 0.7,
    InformationGapCategory.AUTHENTICATION_MAPPING: 0.85,
    InformationGapCategory.AUTHORIZATION_MAPPING: 0.85,
    InformationGapCategory.CLOUD_OWNERSHIP: 0.8,
    InformationGapCategory.VULNERABILITY_TESTING: 0.9,
    InformationGapCategory.PROOF_VALIDATION: 0.85,
    InformationGapCategory.REPLAY: 0.6,
}


class UnknownsEngine:
    """Derive explicit information gaps from the current intelligence state."""

    def analyze(self, state: TargetIntelligenceState) -> list[InformationGap]:
        """Return all open information gaps for a target state."""
        gaps: list[InformationGap] = []
        seen: set[tuple[str, str]] = set()

        def add(
            *,
            asset_key: str,
            category: InformationGapCategory,
            question: str,
            capability: CoverageCapability,
            importance: float | None = None,
            blocking: bool = False,
            risk: str = "passive",
        ) -> None:
            marker = (asset_key, capability.value)
            if marker in seen:
                return
            seen.add(marker)
            gaps.append(
                InformationGap(
                    gap_id=generate_id(),
                    target_id=state.target.target_id,
                    mission_id=state.target.mission_id,
                    asset_key=asset_key,
                    category=category,
                    question=question,
                    importance=importance if importance is not None else _DEFAULT_IMPORTANCE.get(category, 0.5),
                    confidence=0.7,
                    required_capability=capability,
                    candidate_tools=_CANDIDATE_TOOLS.get(capability, ()),
                    risk=risk,
                    blocking=blocking,
                    created_at=utcnow_iso(),
                )
            )

        # Target-level discovery gaps from the coverage matrix.
        for capability, category in (
            (CoverageCapability.SUBDOMAIN_ENUMERATION, InformationGapCategory.SUBDOMAIN_ENUMERATION),
            (CoverageCapability.PORT_DISCOVERY, InformationGapCategory.PORT_DISCOVERY),
            (CoverageCapability.DNS_ENUMERATION, InformationGapCategory.ASSET_DISCOVERY),
            (CoverageCapability.CERTIFICATE_ENUMERATION, InformationGapCategory.ASSET_DISCOVERY),
            (CoverageCapability.CLOUD_OWNERSHIP_MAPPING, InformationGapCategory.CLOUD_OWNERSHIP),
        ):
            if state.coverage.state("", capability) in (CoverageState.UNKNOWN, CoverageState.NOT_ASSESSED):
                add(
                    asset_key="",
                    category=category,
                    question=f"Has {capability.value} been performed for this target?",
                    capability=capability,
                    blocking=capability is CoverageCapability.SUBDOMAIN_ENUMERATION,
                    risk="passive",
                )

        assets = state.assets
        by_kind = _assets_by_kind(assets)

        # Technology unknowns.
        for asset in assets:
            kind = _kind(asset)
            if kind not in (EntityKind.URL.value, EntityKind.SERVICE.value, EntityKind.HOSTNAME.value):
                continue
            if not _has_observation(state, asset.key, "technology"):
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.TECHNOLOGY_FINGERPRINT,
                    question=f"What technology stack serves {asset.key}?",
                    capability=CoverageCapability.TECHNOLOGY_FINGERPRINT,
                    blocking=False,
                )
            if state.coverage.state(asset.key, CoverageCapability.TECHNOLOGY_FINGERPRINT).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.TECHNOLOGY_FINGERPRINT,
                    question=f"Has the technology of {asset.key} been fingerprinted?",
                    capability=CoverageCapability.TECHNOLOGY_FINGERPRINT,
                )

        # Content / endpoint / parameter discovery on web assets.
        web_targets = (
            list(by_kind.get(EntityKind.URL.value, ()))
            + list(by_kind.get(EntityKind.API_ENDPOINT.value, ()))
            + list(by_kind.get(EntityKind.WEBSOCKET_ENDPOINT.value, ()))
        )
        for asset in web_targets:
            if state.coverage.state(asset.key, CoverageCapability.ENDPOINT_ENUMERATION).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.ENDPOINT_MAPPING,
                    question=f"What endpoints exist under {asset.key}?",
                    capability=CoverageCapability.ENDPOINT_ENUMERATION,
                )
            if state.coverage.state(asset.key, CoverageCapability.CONTENT_DISCOVERY).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.CONTENT_DISCOVERY,
                    question=f"What content/paths exist under {asset.key}?",
                    capability=CoverageCapability.CONTENT_DISCOVERY,
                )
            if state.coverage.state(asset.key, CoverageCapability.PARAMETER_DISCOVERY).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.PARAMETER_DISCOVERY,
                    question=f"What parameters does {asset.key} accept?",
                    capability=CoverageCapability.PARAMETER_DISCOVERY,
                )

        # Auth / authorization boundary unknowns.
        for asset in assets:
            kind = _kind(asset)
            if kind in (EntityKind.AUTH_SURFACE.value, EntityKind.AUTH_ENDPOINT.value) and state.coverage.state(
                asset.key, CoverageCapability.AUTHENTICATION_ANALYSIS
            ).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.AUTHENTICATION_MAPPING,
                    question=f"What authentication schemes does {asset.key} expose?",
                    capability=CoverageCapability.AUTHENTICATION_ANALYSIS,
                    blocking=True,
                    risk="low",
                )
            if kind in (EntityKind.ADMIN_SURFACE.value, EntityKind.AUTHORIZATION_ENDPOINT.value) and state.coverage.state(
                asset.key, CoverageCapability.AUTHORIZATION_ANALYSIS
            ).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.AUTHORIZATION_MAPPING,
                    question=f"What authorization boundaries protect {asset.key}?",
                    capability=CoverageCapability.AUTHORIZATION_ANALYSIS,
                    blocking=True,
                    risk="low",
                )

        # API/GraphQL mapping unknowns.
        for asset in assets:
            kind = _kind(asset)
            if kind in (EntityKind.API_ENDPOINT.value, EntityKind.GRAPHQL_ENDPOINT.value, EntityKind.WEBSOCKET_ENDPOINT.value) and state.coverage.state(
                asset.key, CoverageCapability.API_MAPPING
            ).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.API_MAPPING,
                    question=f"What operations does {asset.key} expose?",
                    capability=CoverageCapability.API_MAPPING,
                )
            if kind == EntityKind.GRAPHQL_ENDPOINT.value and state.coverage.state(
                asset.key, CoverageCapability.GRAPHQL_ENUMERATION
            ).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.GRAPHQL_SCHEMA,
                    question=f"What schema does the GraphQL endpoint {asset.key} expose?",
                    capability=CoverageCapability.GRAPHQL_ENUMERATION,
                )

        # Service version unknowns.
        for asset in by_kind.get(EntityKind.SERVICE.value, ()):
            if not asset.properties.get("version"):
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.SERVICE_DETECTION,
                    question=f"What version does service {asset.key} run?",
                    capability=CoverageCapability.SERVICE_DETECTION,
                    risk="passive",
                )

        # Vulnerability state unknowns for testable assets.
        for asset in _testable(assets):
            if state.coverage.state(asset.key, CoverageCapability.VULNERABILITY_SCANNING).uncovered():
                add(
                    asset_key=asset.key,
                    category=InformationGapCategory.VULNERABILITY_TESTING,
                    question=f"What known vulnerabilities affect {asset.key}?",
                    capability=CoverageCapability.VULNERABILITY_SCANNING,
                    importance=0.9,
                )

        return sorted(gaps, key=lambda gap: (-gap.importance, gap.question))


def _kind(asset: IntelligenceAsset) -> str:
    return asset.kind.value if isinstance(asset.kind, EntityKind) else str(asset.kind)


def _assets_by_kind(assets: Sequence[IntelligenceAsset]) -> dict[str, list[IntelligenceAsset]]:
    grouped: dict[str, list[IntelligenceAsset]] = {}
    for asset in assets:
        grouped.setdefault(_kind(asset), []).append(asset)
    return grouped


def _testable(assets: Sequence[IntelligenceAsset]) -> list[IntelligenceAsset]:
    testable = {
        EntityKind.URL.value,
        EntityKind.API_ENDPOINT.value,
        EntityKind.GRAPHQL_ENDPOINT.value,
        EntityKind.SERVICE.value,
        EntityKind.PORT.value,
        EntityKind.CLOUD_RESOURCE.value,
    }
    return [asset for asset in assets if _kind(asset) in testable]


def _has_observation(state: TargetIntelligenceState, asset_key: str, observation_type: str) -> bool:
    """Return ``True`` when the state references an observation of a type.

    ``TargetIntelligenceState`` carries a summary only (observation_count), so
    this helper checks asset properties + any lightweight signal embedded in
    the state (e.g. ``intelligence_state`` counts) to stay O(1).
    """
    return bool(state.target.intelligence_state.get(f"{asset_key}:{observation_type}"))


__all__ = [
    "InformationGap",
    "InformationGapCategory",
    "UnknownCategory",
    "UnknownsEngine",
]
