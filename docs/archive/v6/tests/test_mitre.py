# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for MITRE Mapping
import json
from core.mitre import MITREMapper, MITREMapping


class TestMITREMapping:
    def test_create(self):
        m = MITREMapping(
            finding_category="RCE",
            technique_id="T1203",
            technique_name="Exploitation for Client Execution",
            tactics=["execution"],
            cwe_ids=["CWE-78"],
        )
        assert m.technique_id == "T1203"

    def test_to_dict(self):
        m = MITREMapping(
            finding_category="SQLI",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactics=["initial-access"],
            cwe_ids=["CWE-89", "CWE-79"],
        )
        d = m.to_dict()
        assert d["technique_id"] == "T1190"
        assert len(d["cwe_ids"]) == 2


class TestMITREMapper:
    def test_create(self):
        mm = MITREMapper()
        assert len(mm._database) > 0

    def test_map_rce(self):
        mm = MITREMapper()
        m = mm.map_category("RCE")
        assert m.technique_id == "T1203"
        assert "CWE-78" in m.cwe_ids

    def test_map_sqli(self):
        mm = MITREMapper()
        m = mm.map_category("SQLI")
        assert m.technique_id == "T1190"

    def test_map_lfi(self):
        mm = MITREMapper()
        m = mm.map_category("LFI")
        assert m.technique_id == "T1005"

    def test_map_xss(self):
        mm = MITREMapper()
        m = mm.map_category("XSS")
        assert m.technique_id == "T1059.007"

    def test_map_ssti(self):
        mm = MITREMapper()
        m = mm.map_category("SSTI")
        assert "CWE-94" in m.cwe_ids

    def test_map_ssrf(self):
        mm = MITREMapper()
        m = mm.map_category("SSRF")
        assert m.technique_id == "T1595.002"

    def test_map_open_redirect(self):
        mm = MITREMapper()
        m = mm.map_category("OPEN_REDIRECT")
        assert "CWE-601" in m.cwe_ids

    def test_map_generic(self):
        mm = MITREMapper()
        m = mm.map_category("UNKNOWN_CATEGORY")
        assert m.technique_id == "T1580"

    def test_map_finding(self):
        mm = MITREMapper()
        m = mm.map_finding({"payload_category": "RCE", "payload": "id"})
        assert m.technique_id == "T1203"

    def test_register_mapping(self):
        mm = MITREMapper()
        mm.register_mapping("CUSTOM", {
            "technique_id": "T9999",
            "technique_name": "Custom Technique",
            "tactics": ["custom"],
        })
        m = mm.map_category("CUSTOM")
        assert m.technique_id == "T9999"

    def test_map_findings_dedup(self):
        mm = MITREMapper()
        findings = [
            {"payload_category": "RCE", "payload": "a"},
            {"payload_category": "RCE", "payload": "b"},
            {"payload_category": "SQLI", "payload": "c"},
        ]
        mappings = mm.map_findings(findings)
        assert len(mappings) == 2

    def test_get_mitre_attack_matrix(self):
        mm = MITREMapper()
        findings = [
            {"payload_category": "RCE", "payload": "a"},
            {"payload_category": "SQLI", "payload": "b"},
        ]
        matrix = mm.get_mitre_attack_matrix(findings)
        assert len(matrix) > 0
        assert any("execution" in tactic for tactic in matrix)

    def test_get_coverage(self):
        mm = MITREMapper()
        cov = mm.get_coverage()
        assert cov["total_categories_mapped"] > 0
        assert cov["mitre_techniques"] > 0

    def test_to_dict(self):
        mm = MITREMapper()
        d = mm.to_dict()
        assert "mappings" in d
        assert "coverage" in d

    def test_to_json(self):
        mm = MITREMapper()
        j = mm.to_json()
        parsed = json.loads(j)
        assert "mappings" in parsed
