# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the representative reference adapters and parser/normalizer flow."""

from __future__ import annotations

from hunterx.domain.tool_intelligence import CanonicalObservation, ToolExecutionResult
from hunterx.tools.intelligence.adapters import (
    REFERENCE_ADAPTERS,
    PortScannerAdapter,
    TechDetectorAdapter,
    WebProbeAdapter,
)
from hunterx.tools.intelligence.normalizers import _parse_records
from hunterx.tools.intelligence.parsers import NormalizerRegistry, ParserRegistry


def _metadata(tool_id: str, **overrides) -> dict:
    payload = {
        "tool_id": tool_id,
        "tool_version": "1.0.0",
        "target_id": "example.com",
    }
    payload.update(overrides)
    return payload


class TestReferenceAdapters:
    def test_port_scanner_produces_observations(self) -> None:
        adapter = PortScannerAdapter()
        result = adapter.run(target="example.com", metadata=_metadata("portscanner"))
        assert isinstance(result, ToolExecutionResult)
        assert result.observations
        assert all(isinstance(o, CanonicalObservation) for o in result.observations)
        assert all(o.observation_kind == "port" for o in result.observations)
        assert result.exit_status == "0"

    def test_web_probe_normalizes_urls(self) -> None:
        adapter = WebProbeAdapter()
        observations = adapter.observations(target="example.com", metadata=_metadata("webprobe"))
        assert all(o.observation_kind == "url" for o in observations)
        assert observations[0].normalized_value.startswith("https://")

    def test_tech_detector_normalizes_technology(self) -> None:
        adapter = TechDetectorAdapter()
        observations = adapter.observations(
            target="example.com", metadata=_metadata("techdetector")
        )
        assert all(o.observation_kind == "technology" for o in observations)
        names = {o.value for o in observations}
        assert "Nginx" in names

    def test_reference_registry(self) -> None:
        assert set(REFERENCE_ADAPTERS) == {"portscanner", "webprobe", "techdetector"}
        assert issubclass(REFERENCE_ADAPTERS["portscanner"], PortScannerAdapter)


class TestParserNormalizerFlow:
    def test_parse_records_json_string(self) -> None:
        records = _parse_records('[{"port": 22}, {"port": 443}]', {})
        assert len(records) == 2

    def test_parse_records_jsonl(self) -> None:
        records = _parse_records('{"port": 22}\n{"port": 443}\n', {})
        assert len(records) == 2

    def test_parse_records_garbage(self) -> None:
        assert _parse_records("not json at all", {}) == []

    def test_registries_resolve_custom(self) -> None:
        parsers = ParserRegistry()
        normalizers = NormalizerRegistry()
        parsers.register("mine", _parse_records)
        normalizers.register("tech", lambda r, m: _normalize_tech(r, m))
        from hunterx.tools.intelligence.parsers import ToolRuntimeRegistry

        runtime = ToolRuntimeRegistry(parsers, normalizers)
        parser, normalizer = runtime.resolve("mine", "tech")
        assert callable(parser)
        assert callable(normalizer)


def _normalize_tech(record, metadata):
    from hunterx.domain.tool_intelligence import CanonicalObservation

    return CanonicalObservation(
        observation_id="x",
        target_id=str(metadata.get("target_id", "")),
        tool_id=str(metadata.get("tool_id", "")),
        observation_kind="technology",
        value=str(record.get("name", "")),
    )
