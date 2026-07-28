# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Threat Model Engine
import json
from core.threat_model import (
    ThreatModelEngine,
    ThreatModel,
    Asset,
    DataFlow,
    AssetType,
)


class TestThreatModel:
    def test_create_model(self):
        tm = ThreatModel(id="tm-1", target="http://example.com")
        assert tm.target == "http://example.com"
        assert len(tm.assets) == 0

    def test_add_asset(self):
        tm = ThreatModel(id="tm-1", target="http://example.com")
        asset = Asset(id="a1", name="Web App", asset_type=AssetType.WEB_APPLICATION)
        tm.add_asset(asset)
        assert len(tm.assets) == 1

    def test_add_data_flow(self):
        tm = ThreatModel(id="tm-1", target="http://example.com")
        flow = DataFlow(id="f1", name="API Call", source="web", destination="db")
        tm.add_data_flow(flow)
        assert len(tm.data_flows) == 1

    def test_to_dict(self):
        tm = ThreatModel(id="tm-1", target="http://example.com")
        tm.add_asset(Asset(id="a1", name="Web", asset_type=AssetType.WEB_APPLICATION))
        d = tm.to_dict()
        assert d["target"] == "http://example.com"
        assert len(d["assets"]) == 1

    def test_to_json(self):
        tm = ThreatModel(id="tm-1", target="http://example.com")
        j = tm.to_json()
        parsed = json.loads(j)
        assert parsed["target"] == "http://example.com"


class TestAsset:
    def test_create_asset(self):
        a = Asset(id="a1", name="MyApp", asset_type=AssetType.API_ENDPOINT)
        assert a.asset_type == AssetType.API_ENDPOINT

    def test_asset_to_dict(self):
        a = Asset(id="a1", name="DB", asset_type=AssetType.DATABASE, criticality=0.9)
        d = a.to_dict()
        assert d["criticality"] == 0.9


class TestThreatModelEngine:
    def test_build_empty(self):
        engine = ThreatModelEngine()
        tm = engine.build("http://example.com", [])
        assert tm.target == "http://example.com"
        assert len(tm.assets) >= 1

    def test_build_with_findings(self):
        engine = ThreatModelEngine()
        findings = [
            {"payload_category": "SQLI", "payload": "' OR 1=1",
             "diff_score": 90, "findings": ["SQL error"]},
            {"payload_category": "XSS", "payload": "<script>",
             "diff_score": 70, "findings": ["XSS reflected"]},
        ]
        tm = engine.build("http://example.com", findings)
        assert len(tm.assets) >= 1
        assert len(tm.entry_points) > 0
        assert len(tm.attack_surface) > 0

    def test_build_with_rce_sqli(self):
        engine = ThreatModelEngine()
        findings = [
            {"payload_category": "RCE", "payload": "id",
             "diff_score": 95, "findings": ["RCE confirmed"]},
            {"payload_category": "SQLI", "payload": "' OR 1=1",
             "diff_score": 85, "findings": []},
        ]
        tm = engine.build("http://example.com", findings)
        assert len(tm.critical_components) > 0
        assert any("RCE" in c for c in tm.critical_components)
        assert any("SQLI" in c for c in tm.critical_components)

    def test_build_with_sqli_creates_db_asset(self):
        engine = ThreatModelEngine()
        findings = [
            {"payload_category": "SQLI", "payload": "' OR 1=1",
             "diff_score": 80, "findings": []},
        ]
        tm = engine.build("http://example.com", findings)
        assert len(tm.data_flows) > 0

    def test_build_with_context(self):
        engine = ThreatModelEngine()

        class MockContext:
            headers = {"Authorization": "Bearer test"}
            cookies = {"session": "abc"}

        findings = [
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 75, "findings": []},
        ]
        tm = engine.build("http://example.com", findings, MockContext())
        assert len(tm.authentication_zones) > 0

    def test_analyze_attack_surface(self):
        engine = ThreatModelEngine()
        findings = [
            {"payload_category": "XSS", "payload": "<script>",
             "diff_score": 60, "findings": []},
        ]
        tm = engine.build("http://example.com", findings)
        surface = engine.analyze_attack_surface(tm)
        assert len(surface) > 0

    def test_identify_entry_points(self):
        engine = ThreatModelEngine()

        class MockContext:
            headers = {"Authorization": "Bearer x", "Cookie": "y=z"}
            cookies = {}

        eps = engine.identify_entry_points(MockContext())
        assert len(eps) > 0
