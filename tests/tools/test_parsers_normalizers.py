# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Parser / normalizer contract certification (Sprint 034.5).

Certifies that tool output is parsed into structured records and normalized
into canonical observations with provenance, both online (adapter-driven) and
offline (``tools parse`` / ``tools normalize``).
"""

from __future__ import annotations

import json

from hunterx.platform import build_platform
from hunterx.tools.normalizer import NormalizerEngine
from hunterx.tools.parser import ParserEngine


def _platform():
    return build_platform()


class TestParserEngine:
    def test_generic_json_parse(self):
        parsed = ParserEngine().parse("nmap", json.dumps({"host": "10.0.0.1"}))
        assert parsed == [{"host": "10.0.0.1"}]

    def test_malformed_output_is_tool_execution_error(self):
        from hunterx.domain.exceptions import ToolExecutionError

        try:
            ParserEngine().parse("nmap", "not-json{{{")
        except ToolExecutionError:
            pass
        else:
            raise AssertionError("malformed output must raise ToolExecutionError")


class TestOfflineParse:
    def test_parse_subfinder_jsonl(self):
        service = _platform().toolchain_service
        result = service.parse(
            "subfinder",
            '{"host": "api.example.com", "source": "crt.sh"}\n{"host": "dev.example.com"}\n',
            target="example.com",
        )
        assert result["count"] == 2

    def test_parse_nuclei_jsonl(self):
        service = _platform().toolchain_service
        raw = json.dumps(
            {
                "template-id": "cve-2021-0001",
                "info": {"name": "CVE-2021-0001", "severity": "high"},
                "matched-at": "https://example.com/",
            }
        )
        result = service.parse("nuclei", raw + "\n", target="https://example.com")
        assert result["count"] >= 1
        assert result["records"][0]["requires_validation"] is True

    def test_parse_sqlmap_text(self):
        service = _platform().toolchain_service
        result = service.parse(
            "sqlmap",
            "sqlmap identified the following injection point(s):\nParameter: id (GET)\n    Type: boolean-based blind\n",
            target="https://example.com/",
        )
        assert result["count"] >= 1


class TestNormalizer:
    def test_normalize_produces_canonical_findings(self):
        service = _platform().toolchain_service
        records = [{"kind": "finding", "title": "Open port 443", "severity": "medium", "target": "10.0.0.1"}]
        result = service.normalize("nmap", records)
        assert result["counts"]["findings"] >= 1

    def test_normalizer_engine_asset_projection(self):
        engine = NormalizerEngine(default_tool="nmap")
        output = engine.normalize(
            [{"kind": "asset", "name": "10.0.0.1", "asset_type": "host", "properties": {"os": "linux"}}],
            tool="nmap",
        )
        assert output.assets[0]["name"] == "10.0.0.1"
        assert output.assets[0]["asset_type"] == "host"

    def test_normalizer_engine_evidence_projection(self):
        engine = NormalizerEngine(default_tool="nuclei")
        output = engine.normalize(
            [{"kind": "evidence", "content": "matched-at: https://example.com/", "mime_type": "text/plain"}],
            tool="nuclei",
        )
        assert output.evidence[0].content

    def test_normalizer_offline_parse_then_normalize(self):
        service = _platform().toolchain_service
        parsed = service.parse("subfinder", '{"host": "api.example.com", "source": "crt.sh"}')
        records = parsed["records"]
        assert records
        normalized = service.normalize("subfinder", records)
        assert normalized["counts"]["findings"] >= 1
