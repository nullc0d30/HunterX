# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the cloud intelligence analyzer over golden bundles.

Exercises the evidence-based detector set on deterministic fixtures: AWS, Azure,
GCP, Cloudflare + SaaS, multi-cloud, Kubernetes, stale/dangling resources and a
false-positive plain site that must yield no detections.
"""

from __future__ import annotations

import json
from pathlib import Path

from hunterx.domain.cloud import CloudAnalyzer, CloudInput

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


def _analyze(name: str) -> object:
    return CloudAnalyzer().analyze(_bundle(name))


class TestAwsCdn:
    def test_aws_provider_detected(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(provider.name == "aws" for provider in analysis.providers)

    def test_s3_and_cloudfront_services_detected(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        services = {service.service for service in analysis.services}
        assert {"s3", "cloudfront"} <= services

    def test_bucket_resource_detected(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        buckets = [resource for resource in analysis.storage if resource.storage_kind == "object"]
        assert any(bucket.identifier == "acme-assets" for bucket in buckets)

    def test_region_detected(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(region.region == "us-east-1" for region in analysis.regions)

    def test_public_storage_exposure_indicator(self) -> None:
        analysis = _analyze("aws_cdn_input.json")
        assert any(exposure.kind == "public-storage" for exposure in analysis.exposures)


class TestAzureApp:
    def test_azure_provider_detected(self) -> None:
        analysis = _analyze("azure_app_input.json")
        assert any(provider.name == "azure" for provider in analysis.providers)

    def test_app_service_detected(self) -> None:
        analysis = _analyze("azure_app_input.json")
        services = {service.service for service in analysis.services}
        assert "app-service" in services

    def test_blob_storage_resource_detected(self) -> None:
        analysis = _analyze("azure_app_input.json")
        assert any(storage.identifier == "contosostorage" for storage in analysis.storage)

    def test_subscription_indicator_detected(self) -> None:
        analysis = _analyze("azure_app_input.json")
        assert any(account.kind == "subscription" and account.provider == "azure" for account in analysis.accounts)


class TestGcpRun:
    def test_gcp_provider_detected(self) -> None:
        analysis = _analyze("gcp_run_input.json")
        assert any(provider.name == "gcp" for provider in analysis.providers)

    def test_cloud_run_function_detected(self) -> None:
        analysis = _analyze("gcp_run_input.json")
        assert any(fn.compute_kind == "function" for fn in analysis.compute)

    def test_project_indicator_detected(self) -> None:
        analysis = _analyze("gcp_run_input.json")
        assert any(account.kind == "project" for account in analysis.accounts)


class TestCloudflareSaas:
    def test_cloudflare_provider_detected(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert any(provider.name == "cloudflare" for provider in analysis.providers)

    def test_saas_providers_detected(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        names = {provider.name for provider in analysis.saas_providers}
        assert {"stripe", "sentry", "slack"} <= names

    def test_saas_integration_types(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        types = {integration.integration_type for integration in analysis.saas_integrations}
        assert "payment" in types
        assert "monitoring" in types

    def test_webhooks_detected(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert len(analysis.webhooks) >= 2

    def test_secret_management_reference_detected(self) -> None:
        analysis = _analyze("cloudflare_saas_input.json")
        assert any(secret.name == "WEBHOOK_SECRET" for secret in analysis.secrets)


class TestMultiCloud:
    def test_multi_provider_detected(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        names = {provider.name for provider in analysis.providers}
        assert {"aws", "azure"} <= names

    def test_database_resource_detected(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert any(database.identifier == "prod-db" for database in analysis.databases)

    def test_account_and_role_indicators(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert any(account.kind == "account" and account.provider == "aws" for account in analysis.accounts)
        assert any(role.name == "platform-prod-role" for role in analysis.roles)

    def test_permission_indicator_detected(self) -> None:
        analysis = _analyze("multi_cloud_input.json")
        assert any(permission.action == "s3:GetObject" for permission in analysis.permissions)


class TestKubernetes:
    def test_kubernetes_provider_detected(self) -> None:
        analysis = _analyze("kubernetes_input.json")
        assert any(provider.name == "kubernetes" for provider in analysis.providers)

    def test_cluster_indicator_detected(self) -> None:
        analysis = _analyze("kubernetes_input.json")
        assert len(analysis.kubernetes) >= 1

    def test_container_registry_detected(self) -> None:
        analysis = _analyze("kubernetes_input.json")
        assert any(container.container_kind == "registry" for container in analysis.containers)


class TestStaleDangling:
    def test_dangling_resource_indicator_detected(self) -> None:
        analysis = _analyze("stale_dangling_input.json")
        assert any(exposure.kind == "dangling-resource" for exposure in analysis.exposures)

    def test_dangling_is_intelligence_not_vulnerability(self) -> None:
        analysis = _analyze("stale_dangling_input.json")
        for exposure in analysis.exposures:
            assert "vulnerability" not in exposure.detail.lower()
            assert exposure.confidence <= 0.5


class TestFalsePositives:
    def test_no_cloud_signals_on_plain_site(self) -> None:
        analysis = _analyze("false_positive_input.json")
        assert analysis.providers == []
        assert analysis.services == []
        assert analysis.resources == []
        assert analysis.endpoints == []
        assert analysis.saas_providers == []
        assert analysis.secrets == []
        assert analysis.webhooks == []


class TestSecurityInvariants:
    def test_no_secret_values_reach_observations(self) -> None:
        from hunterx.domain.cloud import record_to_dict

        analysis = _analyze("cloudflare_saas_input.json")
        blob = json.dumps([record_to_dict(item) for item in analysis.all_observations()])
        assert "pk_live_51ABCdefGHIjklMNO" not in blob
        assert "AIzaSyDummyFakeKeyForTestingOnly1234567890" not in blob
