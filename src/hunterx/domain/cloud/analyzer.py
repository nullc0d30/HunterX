# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Cloud & SaaS intelligence analyzer.

The in-process, intelligence-only detection engine. It consumes a
:class:`CloudInput` bundle of already-acquired static material (DNS records,
TLS metadata, HTTP headers, technology observations, script content,
documentation text, observed URLs and previously persisted TIDB hints) and
produces a :class:`CloudAnalysis` of typed observations.

Every detector is evidence-based and deterministic. Provider is never inferred
from branding alone; every conclusion carries an evidence fragment and a
confidence. Sensitive values are redacted or fingerprinted before they reach
any observation.
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from hunterx.domain.cloud.classification import CloudClassifier
from hunterx.domain.cloud.confidence import CloudConfidenceEngine, CloudConfidencePolicy
from hunterx.domain.cloud.models import (
    ApiGatewayResourceObservation,
    CdnResourceObservation,
    CiCdResourceObservation,
    CloudAccountObservation,
    CloudAnalysis,
    CloudDependencyObservation,
    CloudEndpointObservation,
    CloudEnvironmentObservation,
    CloudEvidence,
    CloudExposureObservation,
    CloudIdentityObservation,
    CloudInput,
    CloudIntegrationObservation,
    CloudPermissionObservation,
    CloudProviderObservation,
    CloudRegionObservation,
    CloudResourceObservation,
    CloudRoleObservation,
    CloudServiceObservation,
    ComputeResourceObservation,
    ContainerResourceObservation,
    DatabaseResourceObservation,
    EvidenceStrength,
    EvidenceType,
    KubernetesResourceObservation,
    LoadBalancerResourceObservation,
    MessageInfrastructureObservation,
    SaaSApplicationObservation,
    SaaSIntegrationObservation,
    SaaSProviderObservation,
    SecretManagementObservation,
    StorageResourceObservation,
    WebhookObservation,
)
from hunterx.domain.cloud.providers import (
    ProviderCatalog,
    ProviderMatch,
    extract_aws_account,
    extract_aws_role,
    extract_aws_user,
    extract_azure_subscription,
    extract_gcp_project,
    extract_region,
    infer_integration_type,
)
from hunterx.domain.cloud.redaction import (
    fingerprint,
    safe_context,
    secret_reference_kind,
)

_STRENGTH_TO_DECLARED: dict[EvidenceStrength, float] = {
    EvidenceStrength.STRONG: 0.9,
    EvidenceStrength.MODERATE: 0.7,
    EvidenceStrength.WEAK: 0.45,
}

_CONTEXT_LIMIT = 256
_MAX_URLS = 2000


class CloudAnalyzer:
    """Analyze a static-material bundle into typed cloud observations."""

    def __init__(
        self,
        *,
        catalog: ProviderCatalog | None = None,
        classifier: CloudClassifier | None = None,
        confidence: CloudConfidencePolicy | None = None,
    ) -> None:
        self._catalog = catalog or ProviderCatalog()
        self._classifier = classifier or CloudClassifier()
        self._confidence = CloudConfidenceEngine(confidence or CloudConfidencePolicy())

    def analyze(self, bundle: CloudInput) -> CloudAnalysis:
        """Analyze a bundle and return a :class:`CloudAnalysis`."""
        analysis = CloudAnalysis()
        self._detect_providers(bundle, analysis)
        self._detect_regions(bundle, analysis)
        self._detect_saas(bundle, analysis)
        self._detect_accounts_and_identity(bundle, analysis)
        self._detect_secrets(bundle, analysis)
        self._detect_webhooks(bundle, analysis)
        self._detect_dependencies(bundle, analysis)
        self._detect_exposure(bundle, analysis)
        self._detect_dangling(bundle, analysis)
        self._detect_environments(bundle, analysis)
        self._fold_providers(analysis)
        return analysis

    # -- provider / service / resource detection -----------------------------

    def _detect_providers(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect cloud providers, services, resources and endpoints."""
        matches: list[ProviderMatch] = []
        matched_urls: set[str] = set()

        for record in bundle.records:
            record_dict = _as_dict(record)
            for key in ("cname_target", "value", "target"):
                host = _host_of(record_dict.get(key, ""))
                if host:
                    matched_urls.add(host)
                    matches.extend(self._catalog.match_hostname(host))
            name = _host_of(record_dict.get("name", ""))
            if name and name != bundle.domain:
                matched_urls.add(name)

        for header_name, header_value in bundle.headers:
            matches.extend(self._catalog.match_header(header_name, header_value))

        for certificate in bundle.certificates:
            cert_dict = _as_dict(certificate)
            matches.extend(self._catalog.match_tls(cert_dict))
            for key in ("san", "common_name", "dns_names"):
                for san in _string_list(cert_dict.get(key)):
                    san_host = _host_of(san)
                    if san_host:
                        matched_urls.add(san_host)
                        matches.extend(self._catalog.match_hostname(san_host))

        for technology in bundle.technologies:
            matches.extend(self._catalog.match_technology(_as_dict(technology)))

        for url in bundle.observed_urls[:_MAX_URLS]:
            host = _host_of(url)
            if host:
                matched_urls.add(host)
                matches.extend(self._catalog.match_hostname(host))

        for document in bundle.documents:
            text = str(_as_dict(document).get("text") or _as_dict(document).get("content") or "")
            if text:
                matches.extend(self._catalog.match_documentation(text))

        for script_url, script_content in bundle.scripts:
            script_host = _host_of(script_url)
            if script_host:
                matches.extend(self._catalog.match_hostname(script_host))
            matches.extend(self._catalog.match_javascript(script_content))

        if bundle.html:
            matches.extend(self._catalog.match_documentation(bundle.html[:8192]))

        for hint in bundle.tidb_hints:
            hint_dict = _as_dict(hint)
            provider = hint_dict.get("provider") or hint_dict.get("name")
            if provider:
                normalized = self._classifier.normalize_provider(str(provider))
                matches.append(
                    ProviderMatch(
                        provider=normalized,
                        display_name=str(provider),
                        service=str(hint_dict.get("service") or ""),
                        category=str(hint_dict.get("category") or "unknown"),
                        strength=EvidenceStrength.MODERATE,
                        evidence_type="tidb-intelligence",
                        matched_on=safe_context(str(hint_dict.get("identifier") or "")),
                        detail="previously persisted cloud intelligence",
                    )
                )

        self._materialize_matches(matches, analysis, bundle)

    def _materialize_matches(self, matches: list[ProviderMatch], analysis: Any, bundle: CloudInput) -> None:
        """Convert provider matches into typed observations and record evidence."""
        seen_endpoints: set[str] = set()
        seen_services: set[str] = set()
        seen_resources: set[str] = set()
        seen_regions: set[str] = set()
        for match in matches:
            provider = self._classifier.normalize_provider(match.provider)
            raw_host = _host_of(match.matched_on)
            host_is_real = bool(raw_host) and "." in raw_host and match.evidence_type in ("dns-hostname", "url-pattern")
            endpoint_host = raw_host if host_is_real else (bundle.domain or "")
            environment = self._classifier.classify_environment(endpoint_host, bundle.domain, match.region)
            evidence = _match_evidence(match, bundle.tool_id)
            declared = _STRENGTH_TO_DECLARED[match.strength]

            service_key = f"{provider}|{match.service}|{endpoint_host}"
            if match.service and service_key not in seen_services and match.service not in _PROVIDER_LABELS:
                seen_services.add(service_key)
                analysis.services.append(
                    CloudServiceObservation(
                        provider=provider,
                        service=match.service,
                        category=match.category,
                        region=match.region,
                        endpoint=endpoint_host,
                        environment=environment,
                        confidence=self._confidence.observation_confidence(
                            _with_evidence(CloudServiceObservation, evidence, declared)
                        ),
                        indicators=(match.detail,),
                        evidence=(evidence,),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

            resource_id = _resource_identifier(match, endpoint_host) if host_is_real else ""
            if match.resource_kind and resource_id:
                resource_key = f"{provider}|{match.resource_kind}|{resource_id}"
                if resource_key not in seen_resources:
                    seen_resources.add(resource_key)
                    analysis.resources.append(
                        CloudResourceObservation(
                            provider=provider,
                            resource_kind=match.resource_kind,
                            identifier=resource_id,
                            service=match.service,
                            region=match.region,
                            endpoint=endpoint_host,
                            environment=environment,
                            public=match.exposure,
                            confidence=self._confidence.observation_confidence(
                                _with_evidence(CloudResourceObservation, evidence, declared)
                            ),
                            indicators=(match.detail,),
                            evidence=(evidence,),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
                    self._append_resource(
                        analysis, match, resource_id, endpoint_host, environment, evidence, bundle, declared
                    )

            endpoint_key = f"{provider}|{endpoint_host}"
            if endpoint_host and endpoint_key not in seen_endpoints:
                seen_endpoints.add(endpoint_key)
                plane = self._classifier.classify_plane(endpoint_host, match.service, provider, hint=match.plane)
                exposure = self._classifier.classify_exposure(
                    endpoint_host, provider, public_hint=match.exposure in ("public", "public-indicator")
                )
                analysis.endpoints.append(
                    CloudEndpointObservation(
                        endpoint=endpoint_host,
                        provider=provider,
                        service=match.service,
                        plane=plane,
                        exposure=exposure,
                        region=match.region,
                        environment=environment,
                        domain=bundle.domain,
                        confidence=self._confidence.observation_confidence(
                            _with_evidence(CloudEndpointObservation, evidence, declared)
                        ),
                        indicators=(match.detail,),
                        evidence=(evidence,),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

            if match.region:
                region_key = f"{provider}|{match.region}"
                if region_key not in seen_regions:
                    seen_regions.add(region_key)
                    analysis.regions.append(
                        CloudRegionObservation(
                            provider=provider,
                            region=match.region,
                            resource=resource_id,
                            environment=environment,
                            confidence=declared,
                            indicators=(match.detail,),
                            evidence=(evidence,),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )

            self._track_provider(analysis, provider, match, evidence, bundle)

    def _append_resource(
        self,
        analysis: Any,
        match: ProviderMatch,
        resource_id: str,
        endpoint_host: str,
        environment: str,
        evidence: CloudEvidence,
        bundle: CloudInput,
        declared: float,
    ) -> None:
        """Append a resource-family-specific observation for a match."""
        provider = self._classifier.normalize_provider(match.provider)
        common = {
            "provider": provider,
            "region": match.region,
            "environment": environment,
            "confidence": declared,
            "indicators": (match.detail,),
            "evidence": (evidence,),
            "source": "cloud",
            "tool_id": bundle.tool_id,
            "target_key": bundle.target,
            "correlation_id": _correlation(bundle),
            "mission_id": _mission(bundle),
        }
        if match.resource_kind in ("bucket", "storage"):
            analysis.storage.append(
                StorageResourceObservation(
                    storage_kind="object",
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    public=match.exposure,
                    **_kwargs_for(StorageResourceObservation, common),
                )
            )
        elif match.resource_kind in ("instance", "application"):
            analysis.compute.append(
                ComputeResourceObservation(
                    compute_kind=match.resource_kind,
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    **_kwargs_for(ComputeResourceObservation, common),
                )
            )
        elif match.resource_kind == "function":
            analysis.compute.append(
                ComputeResourceObservation(
                    compute_kind="function",
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    **_kwargs_for(ComputeResourceObservation, common),
                )
            )
        elif match.resource_kind in ("registry", "container"):
            analysis.containers.append(
                ContainerResourceObservation(
                    container_kind=match.resource_kind,
                    identifier=resource_id,
                    registry=endpoint_host,
                    **_kwargs_for(ContainerResourceObservation, common),
                )
            )
        elif match.resource_kind == "cluster":
            analysis.kubernetes.append(
                KubernetesResourceObservation(
                    cluster=match.service,
                    kind="cluster",
                    name=resource_id,
                    endpoint=endpoint_host,
                    **_kwargs_for(KubernetesResourceObservation, common),
                )
            )
        elif match.resource_kind in ("database",):
            analysis.databases.append(
                DatabaseResourceObservation(
                    database_kind="managed",
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    technology=match.service,
                    public=match.exposure,
                    **_kwargs_for(DatabaseResourceObservation, common),
                )
            )
        elif match.resource_kind in ("queue", "topic", "message-infrastructure"):
            analysis.message_infrastructure.append(
                MessageInfrastructureObservation(
                    kind=match.resource_kind,
                    identifier=resource_id,
                    service=match.service,
                    endpoint=endpoint_host,
                    **_kwargs_for(MessageInfrastructureObservation, common),
                )
            )
        elif match.resource_kind in ("api-gateway", "gateway"):
            analysis.gateways.append(
                ApiGatewayResourceObservation(
                    gateway_kind="gateway",
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    backend=match.service,
                    **_kwargs_for(ApiGatewayResourceObservation, common),
                )
            )
        elif match.resource_kind == "cdn":
            analysis.cdns.append(
                CdnResourceObservation(
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    origin=bundle.domain,
                    **_kwargs_for(CdnResourceObservation, common),
                )
            )
        elif match.resource_kind == "load-balancer":
            analysis.load_balancers.append(
                LoadBalancerResourceObservation(
                    identifier=resource_id,
                    endpoint=endpoint_host,
                    **_kwargs_for(LoadBalancerResourceObservation, common),
                )
            )
        elif match.resource_kind == "ci-cd":
            analysis.cicd.append(
                CiCdResourceObservation(
                    kind="pipeline",
                    name=resource_id,
                    endpoint=endpoint_host,
                    **_kwargs_for(CiCdResourceObservation, common),
                )
            )
        elif match.resource_kind in ("identity",):
            analysis.identities.append(
                CloudIdentityObservation(
                    identity_kind=match.resource_kind,
                    name=resource_id,
                    identifier=resource_id,
                    **_kwargs_for(CloudIdentityObservation, common),
                )
            )

    def _track_provider(
        self, analysis: Any, provider: str, match: ProviderMatch, evidence: CloudEvidence, bundle: CloudInput
    ) -> None:
        """Record a provider detection for later aggregation."""
        existing = next((item for item in analysis.providers if item.name == provider), None)
        if existing is None:
            analysis.providers.append(
                CloudProviderObservation(
                    name=provider,
                    display_name=match.display_name,
                    evidence_indicators=(match.detail,),
                    confidence=_STRENGTH_TO_DECLARED[match.strength],
                    evidence=(evidence,),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )
        else:
            merged_indicators = tuple(dict.fromkeys((*existing.evidence_indicators, match.detail)))
            merged_evidence = tuple(dict.fromkeys((*existing.evidence, evidence)))
            analysis.providers[analysis.providers.index(existing)] = CloudProviderObservation(
                name=existing.name,
                display_name=existing.display_name,
                evidence_indicators=merged_indicators,
                confidence=max(existing.confidence, _STRENGTH_TO_DECLARED[match.strength]),
                evidence=merged_evidence,
                source="cloud",
                tool_id=bundle.tool_id,
                target_key=bundle.target,
                correlation_id=existing.correlation_id,
                mission_id=existing.mission_id,
            )

    def _fold_providers(self, analysis: Any) -> None:
        """Fold per-provider detections into a single canonical record each."""
        merged: dict[str, CloudProviderObservation] = {}
        for observation in analysis.providers:
            prior = merged.get(observation.name)
            if prior is None:
                merged[observation.name] = observation
                continue
            merged[observation.name] = CloudProviderObservation(
                name=observation.name,
                display_name=observation.display_name or prior.display_name,
                evidence_indicators=tuple(
                    dict.fromkeys((*prior.evidence_indicators, *observation.evidence_indicators))
                ),
                confidence=max(prior.confidence, observation.confidence),
                evidence=tuple(dict.fromkeys((*prior.evidence, *observation.evidence))),
                source="cloud",
                tool_id=observation.tool_id,
                target_key=observation.target_key,
                correlation_id=observation.correlation_id,
                mission_id=observation.mission_id,
            )
        analysis.providers = list(merged.values())

    # -- SaaS detection ------------------------------------------------------

    def _detect_regions(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect region codes embedded in documentation, scripts and headers."""
        fragments = [bundle.html[:8192]]
        fragments.extend(str(_as_dict(document).get("text") or "") for document in bundle.documents)
        fragments.extend(script_content for _, script_content in bundle.scripts)
        fragments.extend(str(value) for _, value in bundle.headers)
        seen: set[str] = set()
        for fragment in fragments:
            if not fragment:
                continue
            text = safe_context(fragment)
            region = extract_region("auto", text)
            if not region:
                continue
            key = f"region|{region}"
            if key in seen:
                continue
            seen.add(key)
            analysis.regions.append(
                CloudRegionObservation(
                    provider="unknown",
                    region=region,
                    confidence=0.4,
                    indicators=("region code in documentation/configuration",),
                    evidence=(_generic_evidence(EvidenceType.DOCUMENTATION, f"region {region}", bundle.tool_id),),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )

    def _detect_saas(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect SaaS platforms, applications, integrations and webhooks."""
        saas_matches: dict[str, list[ProviderMatch]] = {}
        for record in bundle.records:
            record_dict = _as_dict(record)
            for key in ("cname_target", "value", "target"):
                host = _host_of(record_dict.get(key, ""))
                if host:
                    self._collect_saas(host, bundle, saas_matches, analysis)
        for url in bundle.observed_urls[:_MAX_URLS]:
            host = _host_of(url)
            if host:
                self._collect_saas(host, bundle, saas_matches, analysis)
        for script_url, script_content in bundle.scripts:
            host = _host_of(script_url)
            if host:
                self._collect_saas(host, bundle, saas_matches, analysis)
            self._collect_saas_from_js(script_content, bundle, saas_matches, analysis)
        for technology in bundle.technologies:
            name = str(_as_dict(technology).get("name") or "")
            for match in self._catalog.match_saas_technology(_as_dict(technology)):
                if match.provider in _SAAS_NAMES or name.lower() in _SAAS_NAMES:
                    saas_matches.setdefault(match.provider, []).append(match)
        for hint in bundle.tidb_hints:
            hint_dict = _as_dict(hint)
            saas_name = hint_dict.get("saas_provider") or hint_dict.get("name")
            if saas_name and str(saas_name).lower() in _SAAS_NAMES:
                saas_matches.setdefault(str(saas_name).lower(), []).append(
                    ProviderMatch(
                        provider=str(saas_name).lower(),
                        display_name=str(saas_name),
                        service="",
                        category=_SAAS_CATEGORY.get(str(saas_name).lower(), "unknown"),
                        strength=EvidenceStrength.MODERATE,
                        evidence_type="tidb-intelligence",
                        matched_on="",
                        detail="previously persisted SaaS intelligence",
                    )
                )

        for provider, matches in saas_matches.items():
            self._materialize_saas(provider, matches, bundle, analysis)

    def _collect_saas(
        self, hostname: str, bundle: CloudInput, saas_matches: dict[str, list[ProviderMatch]], analysis: Any
    ) -> None:
        """Collect SaaS hostname matches for a hostname."""
        for match in self._catalog.match_saas_hostname(hostname):
            saas_matches.setdefault(match.provider, []).append(match)

    def _collect_saas_from_js(
        self, content: str, bundle: CloudInput, saas_matches: dict[str, list[ProviderMatch]], analysis: Any
    ) -> None:
        """Collect SaaS SDK matches from script content."""
        for match in self._catalog.match_saas_javascript(content):
            saas_matches.setdefault(match.provider, []).append(match)

    def _materialize_saas(self, provider: str, matches: list[ProviderMatch], bundle: CloudInput, analysis: Any) -> None:
        """Convert SaaS matches into typed SaaS observations."""
        seen: set[str] = set()
        for match in matches:
            category = match.category or _SAAS_CATEGORY.get(provider, "unknown")
            endpoint_host = _host_of(match.matched_on) or bundle.domain
            evidence = _match_evidence(match, bundle.tool_id, source="saas")
            declared = _STRENGTH_TO_DECLARED[match.strength]
            integration_type = infer_integration_type(provider, category)

            key = f"{provider}|{integration_type}|{endpoint_host}"
            if key in seen:
                continue
            seen.add(key)
            if not any(item.name == provider for item in analysis.saas_providers):
                analysis.saas_providers.append(
                    SaaSProviderObservation(
                        name=provider,
                        display_name=match.display_name or provider,
                        provider_kind="saas",
                        confidence=declared,
                        indicators=(match.detail,),
                        evidence=(evidence,),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )
            analysis.saas_applications.append(
                SaaSApplicationObservation(
                    name=match.service or provider,
                    saas_provider=provider,
                    url=endpoint_host,
                    environment=self._classifier.classify_environment(endpoint_host, bundle.domain),
                    confidence=declared,
                    indicators=(match.detail,),
                    evidence=(evidence,),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )
            analysis.saas_integrations.append(
                SaaSIntegrationObservation(
                    saas_provider=provider,
                    integration_type=integration_type,
                    name=match.service or provider,
                    endpoint=endpoint_host,
                    auth_mechanism=_auth_mechanism(match),
                    confidence=declared,
                    indicators=(match.detail,),
                    evidence=(evidence,),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )
            analysis.integrations.append(
                CloudIntegrationObservation(
                    provider=provider,
                    integration_type=integration_type,
                    name=match.service or provider,
                    endpoint=endpoint_host,
                    confidence=declared,
                    indicators=(match.detail,),
                    evidence=(evidence,),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )

    # -- account & identity detection -----------------------------------------

    def _detect_accounts_and_identity(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect cloud account, role, permission and identity indicators."""
        seen_accounts: set[str] = set()
        seen_roles: set[str] = set()
        seen_identities: set[str] = set()
        seen_permissions: set[str] = set()

        fragments = [bundle.html[:8192]]
        fragments.extend(str(_as_dict(document).get("text") or "") for document in bundle.documents)
        fragments.extend(script_content for _, script_content in bundle.scripts)
        fragments.extend(str(value) for _, value in bundle.headers)

        for fragment in fragments:
            if not fragment:
                continue
            text = safe_context(fragment)
            # AWS accounts / roles / users
            account_id = extract_aws_account(text)
            if account_id and account_id != "000000000000":
                key = f"aws|account|{account_id}"
                if key not in seen_accounts:
                    seen_accounts.add(key)
                    analysis.accounts.append(
                        CloudAccountObservation(
                            provider="aws",
                            kind="account",
                            value=account_id,
                            confidence=0.4,
                            indicators=("12-digit AWS account identifier",),
                            evidence=(
                                _generic_evidence(EvidenceType.METADATA, f"AWS account {account_id}", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            role_account, role_name = extract_aws_role(text)
            if role_name:
                key = f"aws|role|{role_account}|{role_name}"
                if key not in seen_roles:
                    seen_roles.add(key)
                    analysis.roles.append(
                        CloudRoleObservation(
                            provider="aws",
                            name=role_name,
                            account=role_account,
                            assume_role=bool(re.search(r"assume|sts:", text)),
                            confidence=0.5,
                            indicators=("AWS IAM role ARN",),
                            evidence=(
                                _generic_evidence(EvidenceType.METADATA, f"AWS role {role_name}", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            user_account, user_name = extract_aws_user(text)
            if user_name:
                key = f"aws|user|{user_name}"
                if key not in seen_identities:
                    seen_identities.add(key)
                    analysis.identities.append(
                        CloudIdentityObservation(
                            provider="aws",
                            identity_kind="user",
                            name=user_name,
                            identifier=user_name,
                            account=user_account,
                            confidence=0.5,
                            indicators=("AWS IAM user ARN",),
                            evidence=(
                                _generic_evidence(EvidenceType.METADATA, f"AWS user {user_name}", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            subscription = extract_azure_subscription(text)
            if subscription:
                key = f"azure|subscription|{subscription}"
                if key not in seen_accounts:
                    seen_accounts.add(key)
                    analysis.accounts.append(
                        CloudAccountObservation(
                            provider="azure",
                            kind="subscription",
                            value=subscription,
                            confidence=0.4,
                            indicators=("Azure subscription/tenant GUID",),
                            evidence=(
                                _generic_evidence(
                                    EvidenceType.METADATA, f"Azure subscription {subscription[:8]}...", bundle.tool_id
                                ),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            project = extract_gcp_project(text)
            if project:
                key = f"gcp|project|{project}"
                if key not in seen_accounts:
                    seen_accounts.add(key)
                    analysis.accounts.append(
                        CloudAccountObservation(
                            provider="gcp",
                            kind="project",
                            value=project,
                            confidence=0.4,
                            indicators=("GCP project identifier",),
                            evidence=(
                                _generic_evidence(EvidenceType.METADATA, f"GCP project {project}", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            self._detect_permissions(text, analysis, bundle, seen_permissions)

    def _detect_permissions(self, text: str, analysis: Any, bundle: CloudInput, seen: set[str]) -> None:
        """Detect documented cloud permission indicators (never validated)."""
        for match in _IAM_ACTION_RE.finditer(text):
            action = match.group(0)
            key = f"permission|{action}"
            if key in seen:
                continue
            seen.add(key)
            provider, _, _ = action.partition(":")
            analysis.permissions.append(
                CloudPermissionObservation(
                    provider=provider,
                    name=action,
                    action=action,
                    confidence=0.4,
                    indicators=("documented cloud IAM action",),
                    evidence=(_generic_evidence(EvidenceType.DOCUMENTATION, f"IAM action {action}", bundle.tool_id),),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )

    # -- secret-management detection -------------------------------------------

    def _detect_secrets(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect secret-management indicators (references/fingerprints only)."""
        seen: set[str] = set()
        fragments = [bundle.html[:8192]]
        fragments.extend(str(_as_dict(document).get("text") or "") for document in bundle.documents)
        fragments.extend(script_content for _, script_content in bundle.scripts)
        for fragment in fragments:
            if not fragment:
                continue
            text = safe_context(fragment)
            for provider, kind, pattern in _SECRET_SERVICE_PATTERNS:
                if pattern.search(text):
                    key = f"{provider}|{kind}"
                    if key in seen:
                        continue
                    seen.add(key)
                    analysis.secrets.append(
                        SecretManagementObservation(
                            provider=provider,
                            kind=kind,
                            name=kind,
                            reference="",
                            fingerprint=fingerprint(kind),
                            confidence=0.5,
                            indicators=(f"{kind} reference observed",),
                            evidence=(
                                _generic_evidence(EvidenceType.DOCUMENTATION, f"{kind} reference", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
            for reference in _SECRET_ENV_RE.findall(text):
                normalized = reference.strip().upper()
                if not normalized:
                    continue
                key = f"env|{normalized}"
                if key in seen:
                    continue
                seen.add(key)
                kind = secret_reference_kind(normalized)
                analysis.secrets.append(
                    SecretManagementObservation(
                        provider="unknown",
                        kind=kind,
                        name=normalized,
                        reference=normalized,
                        fingerprint=fingerprint(normalized),
                        confidence=0.5,
                        indicators=("secret environment-variable reference",),
                        evidence=(
                            _generic_evidence(
                                EvidenceType.DOCUMENTATION, f"secret reference {normalized}", bundle.tool_id
                            ),
                        ),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

    # -- webhook detection ------------------------------------------------------

    def _detect_webhooks(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect inbound/outbound webhook indicators."""
        seen: set[str] = set()
        fragments = [bundle.html[:8192]]
        fragments.extend(str(_as_dict(document).get("text") or "") for document in bundle.documents)
        fragments.extend(script_content for _, script_content in bundle.scripts)
        fragments.extend(url for url in bundle.observed_urls[:_MAX_URLS])
        for fragment in fragments:
            if not fragment:
                continue
            text = safe_context(fragment)
            if _WEBHOOK_HOST_RE.search(text) or "/webhook" in text.lower() or "/hooks" in text.lower():
                endpoint = _webhook_endpoint(text, bundle)
                key = f"webhook|{endpoint}"
                if key in seen:
                    continue
                seen.add(key)
                signing = _webhook_signing(text)
                if _WEBHOOK_HOST_RE.search(text) or _OUTBOUND_WEBHOOK_RE.search(text):
                    direction = "outbound"
                else:
                    direction = "inbound"
                analysis.webhooks.append(
                    WebhookObservation(
                        direction=direction,
                        provider=_webhook_provider(text),
                        endpoint=endpoint,
                        event_type=_webhook_event(text),
                        signing=signing,
                        confidence=0.4,
                        indicators=("webhook endpoint observed",),
                        evidence=(
                            _generic_evidence(EvidenceType.DOCUMENTATION, f"webhook {endpoint}", bundle.tool_id),
                        ),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

    # -- third-party dependency detection ----------------------------------------

    def _detect_dependencies(self, bundle: CloudInput, analysis: Any) -> None:
        """Correlate third-party dependencies (application -> third party -> provider)."""
        seen: set[str] = set()
        for technology in bundle.technologies:
            tech_dict = _as_dict(technology)
            name = str(tech_dict.get("name") or "").strip()
            if not name:
                continue
            key = f"tech|{name.lower()}"
            if key in seen:
                continue
            if _is_third_party_technology(name):
                seen.add(key)
                analysis.dependencies.append(
                    CloudDependencyObservation(
                        name=name,
                        provider=_dependency_provider(name),
                        kind="sdk",
                        endpoint=_dependency_endpoint(name),
                        application=bundle.domain,
                        confidence=0.4,
                        indicators=("third-party technology dependency",),
                        evidence=(_generic_evidence(EvidenceType.TECHNOLOGY, name, bundle.tool_id),),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )
        for script_url, _ in bundle.scripts:
            host = _host_of(script_url)
            if not host:
                continue
            for match in self._catalog.match_saas_hostname(host):
                key = f"dep|{match.provider}"
                if key in seen:
                    continue
                seen.add(key)
                analysis.dependencies.append(
                    CloudDependencyObservation(
                        name=match.provider,
                        provider=match.provider,
                        kind="saas",
                        endpoint=host,
                        application=bundle.domain,
                        confidence=0.4,
                        indicators=("third-party SaaS dependency",),
                        evidence=(_generic_evidence(EvidenceType.JAVASCRIPT, host, bundle.tool_id),),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

    # -- exposure detection ------------------------------------------------------

    def _detect_exposure(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect cloud exposure indicators as intelligence (never vulnerabilities)."""
        seen: set[str] = set()
        for storage in analysis.storage:
            key = f"exposure|{storage.identifier}"
            if key in seen:
                continue
            seen.add(key)
            if storage.public in ("public", "public-indicator"):
                analysis.exposures.append(
                    CloudExposureObservation(
                        kind="public-storage",
                        subject=storage.endpoint or storage.identifier,
                        detail=f"public {storage.provider} storage indicator",
                        confidence=0.5,
                        indicators=("public storage endpoint",),
                        evidence=(
                            _generic_evidence(
                                EvidenceType.URL_PATTERN, storage.endpoint or storage.identifier, bundle.tool_id
                            ),
                        ),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )
        for endpoint in analysis.endpoints:
            if endpoint.plane in ("management", "control") and endpoint.exposure in ("public", "public-indicator"):
                key = f"exposure-mgmt|{endpoint.endpoint}"
                if key in seen:
                    continue
                seen.add(key)
                analysis.exposures.append(
                    CloudExposureObservation(
                        kind="exposed-management-endpoint",
                        subject=endpoint.endpoint,
                        detail=f"publicly reachable {endpoint.provider} {endpoint.plane} endpoint",
                        confidence=0.5,
                        indicators=("public management/control endpoint",),
                        evidence=(_generic_evidence(EvidenceType.URL_PATTERN, endpoint.endpoint, bundle.tool_id),),
                        source="cloud",
                        tool_id=bundle.tool_id,
                        target_key=bundle.target,
                        correlation_id=_correlation(bundle),
                        mission_id=_mission(bundle),
                    )
                )

    # -- dangling-resource indicators -------------------------------------------

    def _detect_dangling(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect potential stale/dangling cloud resource indicators.

        Intelligence only: a domain record that points at a provider hostname
        while documentation indicates the resource was decommissioned is
        recorded as a ``dangling-resource`` exposure indicator — never as a
        takeover vulnerability.
        """
        decommission_markers = (
            "decommission",
            "retired",
            "retirement",
            "removed",
            "deprecated",
            "discontinued",
            "dangling",
            "stale",
            "no longer in use",
            "deleted in 20",
            "shut down",
            "sunset",
            "replaced by",
        )
        hints = [bundle.html[:8192]]
        hints.extend(str(_as_dict(document).get("text") or "") for document in bundle.documents)
        hints.extend(script_content for _, script_content in bundle.scripts)
        decommissioned = False
        for hint in hints:
            lowered = str(hint).lower()
            if any(marker in lowered for marker in decommission_markers):
                decommissioned = True
                break
        if not decommissioned:
            return
        for record in bundle.records:
            record_dict = _as_dict(record)
            record_name = str(record_dict.get("name") or "").strip().lower()
            targets = [
                str(record_dict.get("cname_target") or ""),
                str(record_dict.get("value") or ""),
            ]
            for target in targets:
                host = _host_of(target)
                if not host or host == record_name:
                    continue
                if self._catalog.match_hostname(host) or self._catalog.match_saas_hostname(host):
                    if any(ex.kind == "dangling-resource" and ex.subject == record_name for ex in analysis.exposures):
                        continue
                    analysis.exposures.append(
                        CloudExposureObservation(
                            kind="dangling-resource",
                            subject=record_name,
                            detail=f"potential stale deployment: {record_name} points at {host}",
                            confidence=0.3,
                            indicators=("dangling CNAME-like condition",),
                            evidence=(
                                _generic_evidence(EvidenceType.DNS_CNAME, f"{record_name} -> {host}", bundle.tool_id),
                            ),
                            source="cloud",
                            tool_id=bundle.tool_id,
                            target_key=bundle.target,
                            correlation_id=_correlation(bundle),
                            mission_id=_mission(bundle),
                        )
                    )
                    break

    # -- environment detection ----------------------------------------------------

    def _detect_environments(self, bundle: CloudInput, analysis: Any) -> None:
        """Detect environment classifications from hostname evidence."""
        subjects: list[str] = [bundle.domain] if bundle.domain else []
        for record in bundle.records:
            record_dict = _as_dict(record)
            for key in ("name", "cname_target", "value"):
                subjects.append(str(record_dict.get(key) or ""))
        seen: set[str] = set()
        for subject in subjects:
            classification = self._classifier.classify_environment(subject)
            if classification == "unknown":
                continue
            key = f"env|{classification}|{subject}"
            if key in seen:
                continue
            seen.add(key)
            analysis.environments.append(
                CloudEnvironmentObservation(
                    provider="unknown",
                    environment=classification,
                    subject=subject,
                    confidence=0.4,
                    indicators=("environment naming indicator",),
                    evidence=(_generic_evidence(EvidenceType.DNS_RECORD, subject, bundle.tool_id),),
                    source="cloud",
                    tool_id=bundle.tool_id,
                    target_key=bundle.target,
                    correlation_id=_correlation(bundle),
                    mission_id=_mission(bundle),
                )
            )


# -- analyzer helpers -----------------------------------------------------------


@dataclasses.dataclass(slots=True)
class _Scorable:
    """Minimal confidence-engine input carrying the scored attributes."""

    confidence: float
    source: str = "cloud"
    evidence: tuple[CloudEvidence, ...] = ()


def _as_dict(value: Any) -> dict[str, Any]:
    """Coerce a raw value into a dictionary."""
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        serialized = value.to_dict()
        if isinstance(serialized, dict):
            return serialized
    return {}


def _host_of(value: Any) -> str:
    """Extract a hostname from a URL or hostname string (robust to banners)."""
    from urllib.parse import urlsplit

    candidate = str(value or "").strip().lower()
    if not candidate or candidate == "unknown":
        return ""
    if "://" in candidate:
        try:
            candidate = (urlsplit(candidate).hostname or "").rstrip(".")
        except ValueError:
            return ""
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.split("(", 1)[0].strip()
    tokens = candidate.split()
    if len(tokens) > 1:
        dotted = [token for token in tokens if "." in token]
        candidate = dotted[-1] if dotted else tokens[-1]
    return candidate.rstrip(".")


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _with_evidence(cls: type[Any], evidence: CloudEvidence, declared: float) -> _Scorable:
    """Build a lightweight scorable object to feed the confidence engine."""
    return _Scorable(confidence=declared, evidence=(evidence,), source="cloud")


def _match_evidence(match: ProviderMatch, tool_id: str, *, source: str = "cloud") -> CloudEvidence:
    """Build an evidence fragment from a provider match."""
    return CloudEvidence(
        evidence_type=_evidence_type(match.evidence_type),
        value=safe_context(match.matched_on),
        source=source,
        strength=match.strength,
        tool_id=tool_id,
        detail=match.detail,
    )


def _generic_evidence(evidence_type: EvidenceType, value: str, tool_id: str) -> CloudEvidence:
    """Build a generic evidence fragment."""
    return CloudEvidence(
        evidence_type=evidence_type,
        value=safe_context(value),
        source="cloud",
        strength=EvidenceStrength.MODERATE,
        tool_id=tool_id,
        detail=evidence_type.value,
    )


def _evidence_type(value: str) -> EvidenceType:
    try:
        return EvidenceType(value)
    except ValueError:
        return EvidenceType.OTHER


def _resource_identifier(match: ProviderMatch, endpoint_host: str) -> str:
    """Derive a resource identifier from a match + endpoint hostname."""
    if not endpoint_host:
        return ""
    labels = endpoint_host.split(".")
    if match.resource_kind in ("bucket", "storage", "function", "application") and len(labels) >= 2:
        return labels[0]
    if match.resource_kind == "database" and len(labels) >= 3:
        return labels[0]
    if match.resource_kind in ("registry", "cluster", "queue", "topic", "load-balancer", "cdn", "api-gateway"):
        return ".".join(labels[:2]) if len(labels) >= 2 else endpoint_host
    if match.resource_kind == "identity":
        return labels[0] if labels else endpoint_host
    return endpoint_host


def _kwargs_for(cls: type[Any], common: dict[str, Any]) -> dict[str, Any]:
    """Filter a kwargs mapping down to the fields a dataclass actually declares."""
    names = {field.name for field in dataclasses.fields(cls)}
    return {key: value for key, value in common.items() if key in names}


def _correlation(bundle: CloudInput) -> str:
    return str(getattr(bundle, "correlation_id", "") or "")


def _mission(bundle: CloudInput) -> str:
    return str(getattr(bundle, "mission_id", "") or "")


# -- SaaS classification tables ------------------------------------------------

#: Provider-level labels that must not surface as service observations (they
#: describe the provider itself, not a service).
_PROVIDER_LABELS: frozenset[str] = frozenset(
    {
        "amazon",
        "amazon web services",
        "amazonaws",
        "aws",
        "aws-sdk",
        "azure",
        "azure-sdk",
        "microsoft",
        "microsoft azure",
        "google",
        "google cloud",
        "gcp",
        "google-frontend",
        "route53",
        "cloudflare",
        "firebase",
        "docker",
        "oracle cloud",
        "digitalocean",
        "heroku",
        "vercel",
        "netlify",
        "fastly",
        "akamai",
        "supabase",
    }
)

_SAAS_NAMES: frozenset[str] = frozenset(
    {
        "github",
        "gitlab",
        "jenkins",
        "circleci",
        "slack",
        "microsoft-365",
        "google-workspace",
        "atlassian",
        "notion",
        "salesforce",
        "hubspot",
        "zendesk",
        "datadog",
        "sentry",
        "pagerduty",
        "twilio",
        "sendgrid",
        "mailgun",
        "stripe",
        "shopify",
        "auth0",
        "okta",
        "google-analytics",
        "google-tag-manager",
        "segment",
        "mixpanel",
        "amplitude",
        "fullstory",
        "hotjar",
        "intercom",
        "new-relic",
        "elastic",
        "meta",
        "facebook",
    }
)

_SAAS_CATEGORY: dict[str, str] = {
    "github": "ci-cd",
    "gitlab": "ci-cd",
    "jenkins": "ci-cd",
    "circleci": "ci-cd",
    "slack": "communication",
    "microsoft-365": "identity",
    "google-workspace": "identity",
    "atlassian": "support",
    "notion": "support",
    "salesforce": "crm",
    "hubspot": "crm",
    "zendesk": "support",
    "datadog": "monitoring",
    "sentry": "monitoring",
    "pagerduty": "monitoring",
    "twilio": "communication",
    "sendgrid": "email",
    "mailgun": "email",
    "stripe": "payment",
    "shopify": "payment",
    "auth0": "identity",
    "okta": "identity",
    "google-analytics": "analytics",
    "google-tag-manager": "analytics",
    "segment": "analytics",
    "mixpanel": "analytics",
    "amplitude": "analytics",
    "fullstory": "analytics",
    "hotjar": "analytics",
    "intercom": "support",
    "new-relic": "monitoring",
    "elastic": "monitoring",
    "meta": "analytics",
    "facebook": "analytics",
}


def _auth_mechanism(match: ProviderMatch) -> str:
    if match.provider in ("auth0", "okta", "microsoft-365", "google-workspace"):
        return "oauth"
    if match.evidence_type == "javascript":
        return "oauth"
    return "unknown"


def _is_third_party_technology(name: str) -> bool:
    lowered = name.lower()
    if lowered in _SAAS_NAMES:
        return True
    third_party = (
        "react",
        "next.js",
        "vue",
        "angular",
        "jquery",
        "bootstrap",
        "tailwind",
        "webpack",
        "vite",
        "nginx",
        "apache",
        "redis",
        "postgresql",
        "mysql",
        "mongodb",
        "elasticsearch",
        "kafka",
        "rabbitmq",
        "node.js",
        "express",
        "django",
        "flask",
        "ruby on rails",
        "laravel",
        "spring",
    )
    return any(token in lowered for token in third_party)


def _dependency_provider(name: str) -> str:
    lowered = name.lower()
    if lowered in _SAAS_NAMES:
        return lowered
    if lowered in ("redis", "kafka", "rabbitmq"):
        return "self-hosted"
    return "opensource"


def _dependency_endpoint(name: str) -> str:
    lowered = name.lower()
    hosts = {
        "github": "github.com",
        "gitlab": "gitlab.com",
        "slack": "slack.com",
        "stripe": "stripe.com",
        "sentry": "sentry.io",
        "datadog": "datadoghq.com",
        "auth0": "auth0.com",
        "okta": "okta.com",
    }
    return hosts.get(lowered, "")


# -- regex patterns ------------------------------------------------------------

_IAM_ACTION_RE = re.compile(r"\b[a-z0-9-]+:[A-Z][A-Za-z0-9]*\b")

_WEBHOOK_HOST_RE = re.compile(
    r"(?:hooks\.slack\.com|webhook\.office\.com|hooks\.zapier\.com|api\.telegram\.org|discord(?:app)?\.com/api/webhooks)"
)

_OUTBOUND_WEBHOOK_RE = re.compile(
    r"(?i)(webhook_url|webhook_uri|webhook_endpoint|send_webhook|post.*webhook|outgoing_webhook)"
)

_WEBHOOK_EVENT_RE = re.compile(r"(?i)(?:event[_ ]?type[s]?[\"'\s:=]+)([a-z0-9_.-]+)")

_SIGNING_RE = re.compile(r"(?i)(x-hub-signature|x-signature|webhook_secret|signing_secret|signature_verification)")

_SECRET_SERVICE_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    ("aws", "secrets-manager", re.compile(r"(?i)(aws secrets manager|secretsmanager|arn:aws:secretsmanager)")),
    ("azure", "key-vault", re.compile(r"(?i)(azure key vault|keyvault|vault\.azure\.net)")),
    ("gcp", "secret-manager", re.compile(r"(?i)(secret manager|secretmanager|cloud\.google\.com/secret-manager)")),
    ("hashicorp", "vault", re.compile(r"(?i)(hashicorp vault|vault\.hashicorp|vault:write|vault:read)")),
    ("doppler", "doppler", re.compile(r"(?i)(doppler\.com|dopplerhq|doppler secret)")),
    ("1password", "1password", re.compile(r"(?i)(1password|op://|op-vault)")),
]

_SECRET_ENV_RE = re.compile(
    r"\b(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|AWS_SESSION_TOKEN|AZURE_STORAGE_CONNECTION_STRING|AZURE_CLIENT_SECRET|"
    r"AZURE_TENANT_ID|GOOGLE_APPLICATION_CREDENTIALS|DATABASE_URL|DB_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD|REDIS_URL|"
    r"SECRET_KEY|API_KEY|CLIENT_SECRET|WEBHOOK_SECRET|SIGNING_SECRET|SLACK_SIGNING_SECRET|STRIPE_SECRET_KEY|"
    r"STRIPE_WEBHOOK_SECRET|SUPABASE_SERVICE_ROLE|FIREBASE_ADMIN_SDK)\b"
)


def _webhook_endpoint(text: str, bundle: CloudInput) -> str:
    """Extract a canonical webhook endpoint from matched text."""
    host_match = _WEBHOOK_HOST_RE.search(text)
    if host_match:
        return host_match.group(0)
    for url in bundle.observed_urls[:_MAX_URLS]:
        lowered = url.lower()
        if "/webhook" in lowered or "/hooks" in lowered:
            return safe_context(url, limit=128)
    return "webhook-endpoint"


def _webhook_provider(text: str) -> str:
    lowered = text.lower()
    for provider, marker in (
        ("slack", "hooks.slack.com"),
        ("microsoft", "webhook.office.com"),
        ("zapier", "hooks.zapier.com"),
        ("telegram", "api.telegram.org"),
        ("discord", "discord"),
    ):
        if marker in lowered:
            return provider
    return ""


def _webhook_signing(text: str) -> str:
    if _SIGNING_RE.search(text):
        return "secret-reference"
    return "unknown"


def _webhook_event(text: str) -> str:
    match = _WEBHOOK_EVENT_RE.search(text)
    return match.group(1) if match else ""
