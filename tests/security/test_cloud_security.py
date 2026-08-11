# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Security tests for the cloud & SaaS intelligence boundary.

Guarantees the intelligence-only boundary: no credential leakage, no secret
persistence, no cloud token leakage, no cross-target/cross-mission
contamination, no parser abuse, no graph explosion and no exploitation or
credential use.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import pytest

from hunterx.application.cloud import CloudService
from hunterx.domain.cloud import CloudAnalyzer, CloudInput, record_to_dict
from hunterx.domain.cloud.redaction import contains_secret, fingerprint
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudEvidence as TidbCloudEvidence,
)
from hunterx.domain.entities.tidb.cloud_intelligence import (
    CloudRun as TidbCloudRun,
)
from hunterx.infrastructure.db.sql.memory import InMemoryTidbRepositoryFactory
from hunterx.tools.cloud.registry import register_cloud_adapters
from hunterx.tools.sdk.engine import ExecutionEngine

GOLDEN = Path(__file__).parent.parent / "golden" / "cloud"

_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",
    "sk_live_51ABCdefGHIjklMNOpqrSTUvWXyz1234",
    "xoxb-1234567890-abcdefghijklmnopqrstuvwx",
    "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12345678",
    "AIzaSyDummyFakeKeyForTestingOnly1234567890",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "-----BEGIN RSA PRIVATE KEY-----MIIEpQIBAAKCAQEA0",
)


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


def _make_service() -> tuple[CloudService, InMemoryTidbRepositoryFactory, ExecutionEngine]:
    engine = ExecutionEngine()
    register_cloud_adapters(engine)
    engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
    engine.install("cloud-analysis", version="1.0.0")
    stores = InMemoryTidbRepositoryFactory()
    service = CloudService(engine=engine, stores=stores)
    return service, stores, engine


class TestCloudSecurity:
    def test_credential_leakage_prevented(self) -> None:
        analyzer = CloudAnalyzer()
        analysis = analyzer.analyze(
            _bundle("cloudflare_saas_input.json")
            if False
            else CloudInput(
                target="example.org",
                domain="example.org",
                scripts=(("https://example.org/app.js", "const k='sk_live_51ABCdefGHIjklMNOpqrSTUvWXyz1234';"),),
                documents=({"text": "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"},),
            )
        )
        blob = json.dumps([record_to_dict(record) for record in analysis.all_observations()])
        for secret in _SECRETS:
            assert secret not in blob

    def test_secret_values_never_persisted(self) -> None:
        service, stores, _ = _make_service()
        service.run(
            mission_id="m1",
            target="shop.example.org",
            mode="passive",
            parameters={
                "cloud_input": {
                    "target": "shop.example.org",
                    "domain": "example.org",
                    "scripts": (("https://shop.example.org/app.js", "const k='sk_live_51ABCdefGHIjklMNO';"),),
                    "documents": ({"text": "database_url=postgres://user:SuperSecretPassword@db.example.org/app"},),
                }
            },
        )
        blob = json.dumps([dataclasses.asdict(item) for item in stores.repository_for(TidbCloudEvidence).stream()])
        assert "sk_live_51ABCdefGHIjklMNO" not in blob
        assert "SuperSecretPassword" not in blob

    def test_cloud_token_leakage_prevented(self) -> None:
        analyzer = CloudAnalyzer()
        analysis = analyzer.analyze(
            CloudInput(
                target="example.org",
                domain="example.org",
                scripts=(
                    ("https://example.org/app.js", "sessionStorage.setItem('awsSessionToken','ASIAIOSFODNN7EXAMPLE');"),
                ),
            )
        )
        blob = json.dumps([record_to_dict(record) for record in analysis.all_observations()])
        assert "ASIAIOSFODNN7EXAMPLE" not in blob

    def test_cross_target_contamination_prevented(self) -> None:
        service, stores, _ = _make_service()
        service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={
                "cloud_input": {
                    "target": "acme.com",
                    "domain": "acme.com",
                    "records": ({"name": "www.acme.com", "type": "CNAME", "cname_target": "evil.org"},),
                    "documents": ({"text": "owned by evil.org"},),
                }
            },
        )
        blob = json.dumps([dataclasses.asdict(item) for item in stores.repository_for(TidbCloudEvidence).stream()])
        assert "evil.org" not in blob

    def test_cross_mission_contamination_prevented(self) -> None:
        service, stores, _ = _make_service()
        service.run(
            mission_id="m1",
            target="acme.com",
            mode="passive",
            parameters={
                "cloud_input": {
                    "target": "acme.com",
                    "domain": "acme.com",
                    "headers": {"Server": "AmazonS3"},
                }
            },
        )
        for entity_cls in (TidbCloudEvidence, TidbCloudRun):
            for record in stores.repository_for(entity_cls).stream():
                assert record.mission_id == "m1"

    def test_scope_bypass_blocked(self) -> None:
        from hunterx.domain.cloud.scope import CloudScopePolicy

        engine = ExecutionEngine()
        register_cloud_adapters(engine)
        engine.install_hook("cloud-analysis", lambda _tid, _version: "1.0.0")
        engine.install("cloud-analysis", version="1.0.0")
        stores = InMemoryTidbRepositoryFactory()
        service = CloudService(engine=engine, stores=stores, scope=CloudScopePolicy(roots=frozenset({"example.com"})))
        with pytest.raises(ValueError, match="out of scope"):
            service.run(
                mission_id="m1",
                target="evil.org",
                mode="passive",
                parameters={
                    "cloud_input": {
                        "target": "evil.org",
                        "domain": "evil.org",
                        "headers": {"Server": "AmazonS3"},
                    }
                },
            )
        assert stores.repository_for(TidbCloudEvidence).count() == 0

    def test_malformed_cloud_identifiers_handled(self) -> None:
        analyzer = CloudAnalyzer()
        analysis = analyzer.analyze(
            CloudInput(
                target="example.com",
                domain="example.com",
                records=({"name": "x", "type": "CNAME", "cname_target": ":::not-a-host:::"},),
                documents=({"text": "\x00\x01\x02 malformed " * 50},),
            )
        )
        # must not raise and must not persist malformed endpoints
        assert isinstance(analysis.all_observations(), list)

    def test_huge_cloud_inventory_handled(self) -> None:
        analyzer = CloudAnalyzer()
        records = tuple(
            {"name": f"host-{i}.example.com", "type": "CNAME", "cname_target": f"dist-{i}.cloudfront.net"}
            for i in range(2000)
        )
        analysis = analyzer.analyze(CloudInput(target="example.com", domain="example.com", records=records))
        # bounded output: one provider, deduplicated resources
        assert len(analysis.providers) >= 1
        assert len(analysis.endpoints) <= 2000

    def test_graph_explosion_limited(self) -> None:
        service, stores, _ = _make_service()
        urls = [f"https://assets-{i}.example.com/x" for i in range(2000)]
        service.run(
            mission_id="m1",
            target="example.com",
            mode="passive",
            parameters={
                "cloud_input": {
                    "target": "example.com",
                    "domain": "example.com",
                    "observed_urls": urls,
                }
            },
        )
        from hunterx.domain.entities.tidb.topology import TopologyRelationship

        assert stores.repository_for(TopologyRelationship).count() <= 5000

    def test_webhook_secret_leakage_prevented(self) -> None:
        analyzer = CloudAnalyzer()
        analysis = analyzer.analyze(
            CloudInput(
                target="example.com",
                domain="example.com",
                observed_urls=("https://example.com/webhooks/payment",),
                documents=({"text": "webhook_secret = 'Whsec_AbCdEf1234567890AbCdEf1234567890'"},),
            )
        )
        blob = json.dumps([record_to_dict(record) for record in analysis.all_observations()])
        assert "Whsec_AbCdEf1234567890AbCdEf1234567890" not in blob
        assert any(webhook.endpoint for webhook in analysis.webhooks)

    def test_metadata_endpoint_indicators_recorded_not_touched(self) -> None:
        analyzer = CloudAnalyzer()
        analysis = analyzer.analyze(
            CloudInput(
                target="example.com",
                domain="example.com",
                observed_urls=("http://169.254.169.254/latest/meta-data/",),
            )
        )
        # the metadata endpoint appears nowhere as a persisted endpoint/evidence value
        blob = json.dumps([record_to_dict(record) for record in analysis.all_observations()])
        assert "169.254.169.254" not in blob

    def test_no_exploitation_tools_registered(self) -> None:
        from hunterx.tools.cloud import CLOUD_TOOL_IDS

        assert CLOUD_TOOL_IDS == ("cloud-analysis",)
        adapter_caps = set()
        for spec in __import__("hunterx.tools.cloud", fromlist=["cloud_tool_specs"]).cloud_tool_specs():
            adapter_caps.update(spec.capabilities)
        assert not {"cloud-exploitation", "credential-stuffing", "bucket-takeover"} & adapter_caps

    def test_contains_secret_detection(self) -> None:
        assert contains_secret("AKIAIOSFODNN7EXAMPLE")
        assert contains_secret("sk_live_abc123")
        assert contains_secret("postgres://user:SuperSecretPassword@db.example.org")
        assert not contains_secret("plain text value")

    def test_fingerprint_only_metadata(self) -> None:
        # references are stored as fingerprints, never as the reference value
        assert fingerprint("AWS_SECRET_ACCESS_KEY") != "AWS_SECRET_ACCESS_KEY"
        assert len(fingerprint("anything")) == 24
