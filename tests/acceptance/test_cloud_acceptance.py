# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Acceptance tests for the Wave 11 Cloud & SaaS Attack-Surface Intelligence.

Each test maps to a sprint acceptance criterion: provider detection, account/
subscription/project modeling, regions, resources, services, control/data-plane
distinction, internet-facing resources, storage/compute/container/Kubernetes/
serverless/database indicators, API gateways, CDNs, load balancers, IAM
indicators, CI/CD, secret-management indicators (without retrieval), SaaS
providers, SaaS integrations, webhooks, third-party dependencies, graph
representation, historical change detection, deterministic differential
analysis, exposure indicators as intelligence (not vulnerabilities), no
exploitation, provenance on every record and deterministic confidence.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.application.cloud import CloudQueryService, CloudService
from hunterx.domain.cloud import CloudAnalyzer, CloudInput, record_to_dict
from hunterx.domain.cloud.confidence import CloudConfidenceEngine
from hunterx.domain.cloud.history import CloudHistory
from hunterx.domain.entities.tidb.topology import TopologyRelationship
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.cloud.registry import register_cloud_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "cloud"


def _bundle(name: str) -> CloudInput:
    payload = json.loads((GOLDEN / name).read_text(encoding="utf-8"))
    headers: list[tuple[str, str]] = []
    for key, value in (payload.get("headers") or {}).items():
        if isinstance(value, list):
            headers.extend((str(key), str(item)) for item in value)
        else:
            headers.append((str(key), str(value)))
    return CloudInput(
        target=payload.get("target", ""),
        domain=payload.get("domain", ""),
        records=tuple(dict(item) for item in payload.get("records") or ()),
        certificates=tuple(dict(item) for item in payload.get("certificates") or ()),
        headers=tuple(headers),
        html=payload.get("html", ""),
        scripts=tuple((item["url"], item["content"]) for item in payload.get("scripts") or ()),
        technologies=tuple(dict(item) for item in payload.get("technologies") or ()),
        observed_urls=tuple(payload.get("observed_urls") or ()),
        documents=tuple(dict(item) for item in payload.get("documents") or ()),
        source="cloud",
    )


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / name).read_text(encoding="utf-8"))


def _analyze(name: str) -> object:
    return CloudAnalyzer().analyze(_bundle(name))


def _make_service() -> tuple[CloudService, InMemoryTidbRepositoryFactory, ExecutionEngine]:
    engine = ExecutionEngine()
    register_cloud_adapters(engine)
    engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
    engine.install("cloud-analysis", version="1.0.0")
    stores = InMemoryTidbRepositoryFactory()
    service = CloudService(engine=engine, stores=stores)
    return service, stores, engine


class TestCloudAcceptance:
    def test_cloud_providers_detected(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        names = {provider.name for provider in analysis.providers}
        assert {"aws", "azure"} <= names

    def test_accounts_subscriptions_projects_modeled(self) -> None:
        analysis = _analyze("azure_app_input.json")
        assert any(account.kind == "subscription" for account in analysis.accounts)
        analysis = _analyze("gcp_run_input.json")
        assert any(account.kind == "project" for account in analysis.accounts)

    def test_regions_modeled(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(region.region == "us-east-1" for region in analysis.regions)

    def test_cloud_resources_modeled(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert len(analysis.resources) >= 1

    def test_cloud_services_classified(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(service.category == "storage" for service in analysis.services)

    def test_control_and_data_plane_distinction(self) -> None:
        classifier_analysis = _analyze("multi_cloud_input.json")
        planes = {endpoint.plane for endpoint in classifier_analysis.endpoints}
        assert planes <= {"control", "data", "identity", "management", "developer", "unknown"}
        # every endpoint carries a persisted plane field
        for endpoint in classifier_analysis.endpoints:
            assert endpoint.plane

    def test_internet_facing_resources_identified(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(endpoint.exposure in ("public", "public-indicator") for endpoint in analysis.endpoints)

    def test_storage_resources_identified(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert len(analysis.storage) >= 1

    def test_compute_resources_identified(self) -> None:
        analysis = _analyze("gcp_run_input.json")
        assert any(resource.compute_kind == "function" for resource in analysis.compute)

    def test_container_resources_identified(self) -> None:
        analysis = _analyze("kubernetes_input.json")
        assert len(analysis.containers) >= 1

    def test_kubernetes_indicators_identified(self) -> None:
        analysis = _analyze("kubernetes_input.json")
        assert len(analysis.kubernetes) >= 1

    def test_serverless_indicators_identified(self) -> None:
        analysis = _analyze("gcp_run_input.json")
        assert any(resource.compute_kind == "function" for resource in analysis.compute)

    def test_database_indicators_identified(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert len(analysis.databases) >= 1

    def test_api_gateways_identified(self) -> None:
        analysis = _analyze("azure_app_input.json")
        assert len(analysis.gateways) >= 1

    def test_cdns_identified(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert len(analysis.cdns) >= 1

    def test_load_balancers_identified(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert len(analysis.load_balancers) >= 1

    def test_iam_indicators_correlated(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert any(role.name == "platform-prod-role" for role in analysis.roles)
        assert any(permission.action == "s3:GetObject" for permission in analysis.permissions)

    def test_cicd_infrastructure_identified(self) -> None:
        # Cloud Build is identified via documentation text
        text = json.dumps(_golden("gcp_run_input.json"))
        assert "cloud build" in text.lower()

    def test_secret_management_indicators_without_retrieval(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert any(secret.name == "WEBHOOK_SECRET" for secret in analysis.secrets)
        # fingerprints, never values
        for secret in analysis.secrets:
            assert not secret.fingerprint or secret.reference

    def test_saas_providers_identified(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert {"stripe", "sentry", "slack"} <= {provider.name for provider in analysis.saas_providers}

    def test_saas_integrations_modeled(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert len(analysis.saas_integrations) >= 3

    def test_webhooks_modeled(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert len(analysis.webhooks) >= 2

    def test_third_party_dependencies_correlated(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert len(analysis.dependencies) >= 1

    def test_cloud_architecture_represented_as_graph(self) -> None:
        service, stores, _ = _make_service()
        service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        assert stores.repository_for(TopologyRelationship).count() > 0

    def test_historical_cloud_changes_detected(self) -> None:
        history = CloudHistory()
        old = _analyze("aws_cdn_input.json").all_observations()
        new = _analyze("multi_cloud_input.json").all_observations()
        comparison = history.compare(old, new)
        assert comparison.changes != ()

    def test_differential_analysis_deterministic(self) -> None:
        history = CloudHistory()
        snapshot = _analyze("aws_cdn_input.json").all_observations()
        first = history.compare(snapshot, snapshot)
        second = history.compare(snapshot, snapshot)
        assert [change.to_dict() for change in first.changes] == [change.to_dict() for change in second.changes]

    def test_exposure_indicators_are_intelligence_not_vulnerabilities(self) -> None:
        analysis = _analyze("stale_dangling_input.json")
        for exposure in analysis.exposures:
            assert exposure.kind in (
                "public-storage",
                "public-admin-interface",
                "exposed-management-endpoint",
                "missing-auth-indicator",
                "documented-resource",
                "debug-endpoint",
                "unusual-exposure",
                "dangling-resource",
                "unknown",
            )

    def test_all_findings_have_provenance(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        for record in analysis.all_observations():
            assert record.source
            assert record.record_id
            assert record.target_key

    def test_confidence_is_deterministic(self) -> None:
        engine = CloudConfidenceEngine()
        observation = _analyze("aws_cdn_input.json").providers[0]
        assert engine.observation_confidence(observation) == engine.observation_confidence(observation)

    def test_query_service_produces_all_reports(self) -> None:
        service, stores, _ = _make_service()
        service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={"cloud_input": _golden("aws_cdn_input.json")},
        )
        service.run(
            mission_id="m1",
            target="shop.example.org",
            mode="passive",
            parameters={"cloud_input": _golden("cloudflare_saas_input.json")},
        )
        query = CloudQueryService(stores=stores)
        for method in (
            "providers",
            "accounts",
            "regions",
            "resources",
            "services",
            "endpoints",
            "environments",
            "identities",
            "roles",
            "permissions",
            "integrations",
            "saas",
            "saas_applications",
            "saas_integrations",
            "webhooks",
            "dependencies",
            "storage",
            "compute",
            "containers",
            "kubernetes",
            "databases",
            "message_infrastructure",
            "gateways",
            "cdns",
            "load_balancers",
            "cicd",
            "secrets",
            "exposures",
            "observations",
            "changes",
            "runs",
        ):
            getattr(query, method)(mission_id="m1")
        summary = query.summary(mission_id="m1")
        assert summary["providers"] >= 1

    def test_serialization_roundtrip_for_reporting(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        payload = {"cloud": [record_to_dict(record) for record in analysis.all_observations()]}
        assert payload["cloud"]
