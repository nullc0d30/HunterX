# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Attack Chain Engine
import json
from core.attack_chain import (
    AttackChainEngine,
    AttackPath,
    ChainTransition,
    ChainStatus,
    ChainPluginInterface,
)


class TestChainStatus:
    def test_status_values(self):
        assert ChainStatus.HYPOTHETICAL.value == "hypothetical"
        assert ChainStatus.CONFIRMED.value == "confirmed"


class TestChainTransition:
    def test_create_transition(self):
        t = ChainTransition(
            source_finding="LFI",
            target_finding="CONFIGURATION_DISCLOSURE",
            technique="Path traversal",
            confidence=0.75,
            evidence=["Evidence 1"],
            requirements=["Unrestricted file read"],
            estimated_likelihood=0.7,
            risk_increase=0.2,
        )
        assert t.source_finding == "LFI"
        assert t.target_finding == "CONFIGURATION_DISCLOSURE"
        assert t.confidence == 0.75

    def test_to_dict(self):
        t = ChainTransition(
            source_finding="A", target_finding="B", technique="T", confidence=0.5
        )
        d = t.to_dict()
        assert d["source"] == "A"
        assert d["target"] == "B"


class TestAttackPath:
    def test_create_path(self):
        t = ChainTransition(
            source_finding="LFI", target_finding="RCE",
            technique="Log poisoning", confidence=0.7,
        )
        path = AttackPath(
            id="path-1",
            name="LFI -> RCE",
            steps=[t],
            overall_confidence=0.7,
            total_risk=0.5,
        )
        assert path.name == "LFI -> RCE"
        assert len(path.steps) == 1

    def test_to_dict(self):
        t = ChainTransition(
            source_finding="A", target_finding="B", technique="T", confidence=0.5
        )
        path = AttackPath(id="p1", name="A->B", steps=[t])
        d = path.to_dict()
        assert d["name"] == "A->B"
        assert len(d["steps"]) == 1

    def test_summary(self):
        t = ChainTransition(
            source_finding="SQLI", target_finding="EXFIL",
            technique="Union select", confidence=0.8,
        )
        path = AttackPath(id="p1", name="SQLI -> EXFIL", steps=[t])
        s = path.summary()
        assert "SQLI" in s
        assert "EXFIL" in s


class TestAttackChainEngine:
    def test_default_chains_loaded(self):
        engine = AttackChainEngine()
        assert "LFI" in engine._chains
        assert "XSS" in engine._chains
        assert "RCE" in engine._chains
        assert "SQLI" in engine._chains

    def test_build_attack_paths_empty(self):
        engine = AttackChainEngine()
        paths = engine.build_attack_paths([])
        assert paths == []

    def test_build_attack_paths_lfi(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 80, "findings": ["File read confirmed"]},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0
        assert any("LFI" in p.name for p in paths)

    def test_build_attack_paths_xss(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "XSS", "payload": "<script>",
             "diff_score": 70, "findings": ["XSS detected"]},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0

    def test_build_attack_paths_rce(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "RCE", "payload": "id",
             "diff_score": 95, "findings": ["RCE confirmed"]},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0
        rce_paths = [p for p in paths if "RCE" in p.name]
        assert len(rce_paths) > 0

    def test_build_attack_paths_sqli(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "SQLI", "payload": "' OR 1=1",
             "diff_score": 85, "findings": ["SQL error"]},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0

    def test_build_attack_paths_ssrf(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "SSRF", "payload": "http://169.254.169.254",
             "diff_score": 75, "findings": ["Metadata accessed"]},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0

    def test_register_chain(self):
        engine = AttackChainEngine()
        engine.register_chain("CUSTOM", [
            {"target": "PWNED", "technique": "Magic", "confidence": 1.0,
             "evidence_template": "test", "likelihood": 1.0, "risk_increase": 1.0},
        ])
        findings = [
            {"payload_category": "CUSTOM", "payload": "test",
             "diff_score": 100, "findings": []},
        ]
        paths = engine.build_attack_paths(findings)
        assert len(paths) > 0

    def test_register_plugin(self):
        class MockPlugin(ChainPluginInterface):
            def can_handle(self, s, t):
                return s == "TEST" and t == "RESULT"

            def build_transition(self, s, t, ctx=None):
                return ChainTransition(
                    source_finding=s, target_finding=t,
                    technique="plugin", confidence=1.0,
                )

        engine = AttackChainEngine()
        engine.register_plugin(MockPlugin())
        assert len(engine.plugins) == 1

    def test_to_dict(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 80, "findings": ["test"]},
        ]
        paths = engine.build_attack_paths(findings)
        d = engine.to_dict(paths)
        assert isinstance(d, list)

    def test_to_json(self):
        engine = AttackChainEngine()
        findings = [
            {"payload_category": "LFI", "payload": "/etc/passwd",
             "diff_score": 80, "findings": []},
        ]
        paths = engine.build_attack_paths(findings)
        j = engine.to_json(paths)
        parsed = json.loads(j)
        assert isinstance(parsed, list)
