# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0
#
# Tests for Purple Team Output
import tempfile
import os
import pytest
from core.purple import PurpleTeamOutput
from core.mitre import MITREMapper


@pytest.fixture
def sample_findings():
    return [
        {
            "payload_category": "RCE",
            "payload": "id; whoami",
            "diff_score": 95,
            "findings": ["uid=0(root)", "RCE confirmed"],
        },
        {
            "payload_category": "SQLI",
            "payload": "' OR 1=1",
            "diff_score": 85,
            "findings": ["SQL syntax error"],
        },
        {
            "payload_category": "XSS",
            "payload": "<script>alert(1)</script>",
            "diff_score": 70,
            "findings": ["Payload reflected"],
        },
    ]


class TestPurpleTeamOutput:
    def test_create(self):
        pto = PurpleTeamOutput()
        assert len(pto._rules) == 7

    def test_generate_all(self, sample_findings):
        with tempfile.TemporaryDirectory() as tmpdir:
            pto = PurpleTeamOutput(output_dir=tmpdir)
            rules = pto.generate_all(sample_findings, save=True)
            assert len(rules["sigma"]) > 0
            assert len(rules["yara"]) > 0
            assert len(rules["suricata"]) > 0
            assert len(rules["elastic"]) > 0
            assert len(rules["splunk"]) > 0
            assert len(rules["sentinel"]) > 0
            assert len(rules["qradar"]) > 0

    def test_generate_all_saves_files(self, sample_findings):
        with tempfile.TemporaryDirectory() as tmpdir:
            pto = PurpleTeamOutput(output_dir=tmpdir)
            pto.generate_all(sample_findings, save=True)
            base = os.path.join(tmpdir, "purple_team")
            assert os.path.exists(base)
            assert os.path.exists(os.path.join(base, "sigma_rules.yml"))
            assert os.path.exists(os.path.join(base, "yara_rules.yar"))
            assert os.path.exists(os.path.join(base, "suricata_rules.rules"))
            assert os.path.exists(os.path.join(base, "elastic_rules.yml"))
            assert os.path.exists(os.path.join(base, "splunk_searches.spl"))
            assert os.path.exists(os.path.join(base, "sentinel_rules.kql"))
            assert os.path.exists(os.path.join(base, "qradar_rules.txt"))
            assert os.path.exists(os.path.join(base, "manifest.json"))

    def test_generate_all_no_save(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        assert len(rules["sigma"]) > 0

    def test_generate_with_mitre_mappings(self, sample_findings):
        mapper = MITREMapper()
        mappings = mapper.map_findings(sample_findings)
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, mitre_mappings=mappings, save=False)
        assert len(rules["sigma"]) > 0

    def test_generate_with_empty_findings(self):
        pto = PurpleTeamOutput()
        rules = pto.generate_all([])
        assert len(rules["sigma"]) == 0

    def test_get_rules_summary(self, sample_findings):
        pto = PurpleTeamOutput()
        pto.generate_all(sample_findings, save=False)
        summary = pto.get_rules_summary()
        assert summary["sigma"] > 0
        assert summary["yara"] > 0
        assert summary["elastic"] > 0

    def test_sigma_rule_format(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        for rule in rules["sigma"]:
            assert "title:" in rule
            assert "detection:" in rule
            assert "condition:" in rule

    def test_yara_rule_format(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        for rule in rules["yara"]:
            assert "rule" in rule
            assert "strings:" in rule

    def test_suricata_rule_format(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        for rule in rules["suricata"]:
            assert "alert" in rule
            assert "sid:" in rule

    def test_elastic_rule_format(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        for rule in rules["elastic"]:
            assert "query:" in rule

    def test_splunk_search_format(self, sample_findings):
        pto = PurpleTeamOutput()
        rules = pto.generate_all(sample_findings, save=False)
        for rule in rules["splunk"]:
            assert "web_logs" in rule or "|" in rule
