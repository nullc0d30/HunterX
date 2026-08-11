# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Tests for the technology fingerprinting tool adapters.

Each adapter is exercised with a fake binary runner fed golden output (httpx
JSONL, whatweb JSON), or an injectable fetch callable for the in-process
signature detector, so no external tool or network is required. Tests assert
the generated command line and the canonical technology observations attached
to the execution output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunterx.domain.execution import ExecutionContext
from hunterx.domain.technology.detector import HttpEvidence
from hunterx.tools.recon.runner import BinaryRunner, CommandResult
from hunterx.tools.sdk.context import ExecutionContextBuilder
from hunterx.tools.sdk.engine import ExecutionEngine
from hunterx.tools.sdk.output import OutputCollector
from hunterx.tools.tech.httpx import HttpxAdapter
from hunterx.tools.tech.registry import (
    TECH_TOOL_IDS,
    TechAdapterFactory,
    register_tech_adapters,
    tech_adapters,
)
from hunterx.tools.tech.signature import SignatureAdapter
from hunterx.tools.tech.tip import register_tech_tools, tech_tool_specs
from hunterx.tools.tech.whatweb import WhatWebAdapter

GOLDEN = Path(__file__).parent.parent / "golden" / "tech"


class FakeRunner(BinaryRunner):
    """Binary runner that returns a canned :class:`CommandResult`."""

    def __init__(self, result: CommandResult | None = None, *, stdout: str = "") -> None:
        super().__init__()
        self._result = result or CommandResult(returncode=0, stdout=stdout)
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float = 0.0,
        tool_id: str = "",
    ) -> CommandResult:
        self.calls.append(tuple(argv))
        return self._result


def _context(tool_id: str, *, target: str = "example.com", params: dict[str, object] | None = None) -> ExecutionContext:
    builder = ExecutionContextBuilder(tool_id=tool_id, target=target).with_permissions(("network",))
    if params:
        builder = builder.with_parameters(params)
    return builder.build()


def _collect(adapter, context: ExecutionContext) -> OutputCollector:
    collector = OutputCollector()
    adapter.run(context, collector)
    return collector


def _payload(collector: OutputCollector) -> dict[str, object]:
    return collector.build().json or {}


def _observations(collector: OutputCollector) -> list[dict[str, object]]:
    payload = _payload(collector)
    observations = payload["technologies"]
    assert isinstance(observations, list)
    return observations


def _names(collector: OutputCollector) -> set[str]:
    return {str(observation["canonical_name"]) for observation in _observations(collector)}


def _golden(name: str) -> str:
    return (GOLDEN / name).read_text(encoding="utf-8")


class TestHttpxAdapter:
    def test_default_argv(self) -> None:
        adapter = HttpxAdapter()
        argv = adapter.build_argv(_context("httpx"))
        assert argv[:3] == ["httpx", "-u", "example.com"]
        assert "-json" in argv and "-tech-detect" in argv
        assert "-cdn" in argv

    def test_threads_and_rate(self) -> None:
        adapter = HttpxAdapter()
        argv = adapter.build_argv(_context("httpx", params={"threads": 25, "rate_limit": 50, "timeout": 5}))
        assert argv[argv.index("-threads") + 1] == "25"
        assert argv[argv.index("-rate-limit") + 1] == "50"
        assert argv[argv.index("-timeout") + 1] == "5"

    def test_parses_golden_output(self) -> None:
        adapter = HttpxAdapter(runner=FakeRunner(stdout=_golden("httpx_tech.jsonl")))
        collector = _collect(adapter, _context("httpx"))
        observations = _observations(collector)
        assert len(observations) >= 6
        names = {str(obs["canonical_name"]) for obs in observations}
        assert "Nginx" in names
        assert "PHP" in names
        assert "React" in names
        assert "WordPress" in names
        assert "Cloudflare" in names
        nginx = next(obs for obs in observations if obs["canonical_name"] == "Nginx")
        assert nginx["version"] == "1.24.0"
        wordpress = next(obs for obs in observations if obs["canonical_name"] == "WordPress")
        assert wordpress["version"] == "6.4.3"

    def test_malformed_lines_are_skipped(self) -> None:
        adapter = HttpxAdapter(runner=FakeRunner(stdout=_golden("httpx_malformed.jsonl")))
        collector = _collect(adapter, _context("httpx"))
        names = _names(collector)
        assert "React" in names
        assert "Django" in names
        assert "Nginx" in names

    def test_cdn_detection(self) -> None:
        adapter = HttpxAdapter(runner=FakeRunner(stdout=_golden("httpx_tech.jsonl")))
        collector = _collect(adapter, _context("httpx"))
        names = _names(collector)
        assert "Cloudflare" in names

    def test_conflicting_cdn_golden(self) -> None:
        adapter = HttpxAdapter(runner=FakeRunner(stdout=_golden("httpx_conflicting_cdn.jsonl")))
        collector = _collect(adapter, _context("httpx", target="cdn.example.com"))
        names = _names(collector)
        assert "Cloudflare" in names
        assert "React" in names


class TestWhatWebAdapter:
    def test_default_argv(self) -> None:
        adapter = WhatWebAdapter()
        argv = adapter.build_argv(_context("whatweb"))
        assert argv[:4] == ["whatweb", "--no-errors", "--log-json=-", "--quiet"]
        assert argv[-1] == "example.com"

    def test_aggression_param(self) -> None:
        adapter = WhatWebAdapter()
        argv = adapter.build_argv(_context("whatweb", params={"aggression": 3}))
        assert argv[argv.index("--aggression") + 1] == "3"

    def test_parses_golden_output(self) -> None:
        adapter = WhatWebAdapter(runner=FakeRunner(stdout=_golden("whatweb_tech.json")))
        collector = _collect(adapter, _context("whatweb", target="shop.example.com"))
        observations = _observations(collector)
        names = {str(obs["canonical_name"]) for obs in observations}
        assert "Nginx" in names
        assert "PHP" in names
        assert "React" in names
        assert "Cloudflare" in names
        nginx = next(obs for obs in observations if obs["canonical_name"] == "Nginx")
        assert nginx["version"] == "1.24.0"

    def test_certainty_drives_confidence(self) -> None:
        adapter = WhatWebAdapter(runner=FakeRunner(stdout=_golden("whatweb_tech.json")))
        collector = _collect(adapter, _context("whatweb", target="blog.example.com"))
        wordpress = next(obs for obs in _observations(collector) if obs["canonical_name"] == "WordPress")
        assert float(wordpress["confidence"]) == pytest.approx(1.0)


class TestSignatureAdapter:
    def test_descriptor_is_in_process(self) -> None:
        adapter = SignatureAdapter()
        assert adapter.descriptor.name == "signature"
        assert adapter.build_argv(_context("signature")) == []

    def test_detects_from_fetched_evidence(self) -> None:
        def fetch(url: str, timeout: float) -> HttpEvidence:
            return HttpEvidence(
                url=url,
                status_code=200,
                headers={"Server": "nginx/1.24.0", "cf-ray": "xyz"},
                html=_golden("signature_wordpress.html"),
                meta={"generator": "WordPress 6.4.3"},
            )

        adapter = SignatureAdapter(fetch=fetch)
        collector = _collect(adapter, _context("signature", target="blog.example.com"))
        observations = _observations(collector)
        names = {str(obs["canonical_name"]) for obs in observations}
        assert "Nginx" in names
        assert "WordPress" in names
        assert "Cloudflare" in names
        wordpress = next(obs for obs in observations if obs["canonical_name"] == "WordPress")
        assert wordpress["version"] == "6.4.3"

    def test_angular_detection(self) -> None:
        def fetch(url: str, timeout: float) -> HttpEvidence:
            return HttpEvidence(url=url, status_code=200, html=_golden("signature_angular.html"))

        adapter = SignatureAdapter(fetch=fetch)
        collector = _collect(adapter, _context("signature", target="app.example.com"))
        names = _names(collector)
        assert "Angular" in names
        angular = next(obs for obs in _observations(collector) if obs["canonical_name"] == "Angular")
        assert angular["version"] == "16.2.0"

    def test_scheme_fallback(self) -> None:
        fetched: list[str] = []

        def fetch(url: str, timeout: float) -> HttpEvidence:
            fetched.append(url)
            if url.startswith("http://"):
                return HttpEvidence(url=url, status_code=200, headers={"Server": "nginx"})
            return HttpEvidence(url=url)

        adapter = SignatureAdapter(fetch=fetch)
        collector = _collect(adapter, _context("signature", target="example.com"))
        assert fetched[0].startswith("https://")
        assert fetched[1].startswith("http://")
        assert _names(collector) == {"Nginx"}

    def test_fetch_error_degrades_gracefully(self) -> None:
        def fetch(url: str, timeout: float) -> HttpEvidence:
            raise RuntimeError("boom")

        adapter = SignatureAdapter(fetch=fetch)
        collector = _collect(adapter, _context("signature", target="example.com"))
        assert _observations(collector) == []


class TestRegistry:
    def test_tech_tool_ids(self) -> None:
        assert TECH_TOOL_IDS == ("httpx", "whatweb", "signature")

    def test_factory_builds_all(self) -> None:
        adapters = TechAdapterFactory().build()
        assert set(adapters) == set(TECH_TOOL_IDS)

    def test_register_on_engine(self) -> None:
        engine = ExecutionEngine()
        mapping = register_tech_adapters(engine)
        for tool_id in TECH_TOOL_IDS:
            assert engine.adapter_for(tool_id) is mapping[tool_id]

    def test_adapters_helper(self) -> None:
        assert set(tech_adapters()) == set(TECH_TOOL_IDS)


class TestTip:
    def test_specs_match_descriptors(self) -> None:
        specs = tech_tool_specs()
        assert {spec.tool_id for spec in specs} == set(TECH_TOOL_IDS)
        versions = {spec.tool_id: spec.version for spec in specs}
        assert versions["httpx"] == HttpxAdapter.descriptor.version
        assert versions["whatweb"] == WhatWebAdapter.descriptor.version

    def test_register_tools(self) -> None:
        from hunterx.tools.intelligence.api import ToolIntelligenceAPI

        tip = ToolIntelligenceAPI()
        register_tech_tools(tip)
        assert tip.get_tool("httpx") is not None
        assert tip.get_tool("whatweb") is not None
        assert tip.get_tool("signature") is not None
        assert "technology-fingerprinting" in tip.get_knowledge("httpx").capabilities
        metadata = {tool.tool_id for tool in tip.registry.list_metadata()}
        assert set(metadata) == set(TECH_TOOL_IDS)


class TestPipeline:
    def test_adapter_end_to_end_through_sdk(self) -> None:
        engine = ExecutionEngine()
        adapters = register_tech_adapters(engine)
        for tool_id in adapters:
            engine.install_hook(tool_id, lambda _tid, _version: "1.0.0")
            engine.install(tool_id, version="1.0.0")
        adapters["httpx"]._runner = FakeRunner(stdout=_golden("httpx_tech.jsonl"))
        adapters["whatweb"]._runner = FakeRunner(stdout=_golden("whatweb_tech.json"))

        def fetch(url: str, timeout: float) -> HttpEvidence:
            return HttpEvidence(
                url=url,
                status_code=200,
                headers={"Server": "nginx/1.24.0"},
                html=_golden("signature_wordpress.html"),
            )

        adapters["signature"]._fetch = fetch
        context = _context("httpx", target="shop.example.com")
        outcome = engine.execute(context)
        assert outcome.result.status.is_success
        assert outcome.result.output.json is not None
        assert len(outcome.result.output.json["technologies"]) > 0
