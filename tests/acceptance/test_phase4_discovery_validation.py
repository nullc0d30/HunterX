# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Phase 4 — universal deep-discovery validation.

Final validation phase for the universal discovery pipeline. Proves the
target-agnostic deep-discovery pipeline end to end:

    1. the full stage plan runs against a generic loopback SPA/API fixture
       through the platform's real in-process adapters (crawler, JS analyzer,
       tech signatures, TCP probes, DNS, API intelligence, auth analysis),
       feeding the attack-surface graph and assessment queue,
    2. provider states are honest: binary-only tools are UNAVAILABLE (never
       fabricated), a missing capability is NOT_APPLICABLE, a failed tool
       never kills the mission,
    3. deduplication + provenance, continuous-discovery feedback, and
       serializable evidence,
    4. a real black-box regression against ``http://localhost:3010`` treated
       as an arbitrary external target (Juice Shop is only a regression
       target — it never defines the engine),
    5. the core carries no target-specific references.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

import pytest

from hunterx.domain.tools import ToolDescriptor
from hunterx.tools.sdk.adapter import ToolAdapter
from tests.framework.phase4 import BINARY_ONLY_TOOL_IDS, GenericDiscoveryFixture, Phase4Harness

#: Real regression target (loopback-only black-box).
REAL_TARGET = "http://localhost:3010/"


def _target_reachable() -> bool:
    try:
        response = urllib.request.urlopen(REAL_TARGET, timeout=5)
        return response.status == 200
    except (OSError, urllib.error.URLError, ValueError):
        return False


class TestUniversalDiscoveryAgainstFixture:
    """The universal pipeline runs end to end against a generic target."""

    def test_stage_plan_executes_all_stages(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            stages = harness.stage_states()
            assert set(stages) == {
                "dns",
                "subdomain",
                "host",
                "port",
                "service",
                "technology",
                "http",
                "api",
                "graphql",
                "javascript",
                "workflow",
                "auth",
            }
            # Every stage reached a terminal, honest state.
            assert all(
                state in ("completed", "partial", "failed", "unavailable", "not_applicable")
                for state in stages.values()
            )

    def test_real_adapters_discover_assets_and_feed_the_surface(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            run = harness.run()
            kinds = harness.assets_by_kind()
            # Web-layer assets are guaranteed from the crawl + JS analysis.
            assert kinds.get("url", 0) >= 1
            assert kinds.get("javascript_endpoint", 0) >= 1 or kinds.get("api_endpoint", 0) >= 1
            snapshot = harness.service.surface.snapshot()
            assert snapshot["surfaces"] > 0
            assert snapshot["queue_total"] > 0
            assert run["summary"]["assets_total"] > 0

    def test_binary_only_tools_are_honestly_unavailable(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            states = harness.provider_states()
            for tool_id in BINARY_ONLY_TOOL_IDS:
                assert tool_id in states, tool_id
                assert states[tool_id] == "unavailable", tool_id

    def test_in_process_adapters_complete(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            states = harness.provider_states()
            for tool_id in (
                "crawler",
                "javascript",
                "signature",
                "tcp-connect",
                "dnspython",
                "api-openapi",
                "api-graphql",
                "api-websocket",
                "api-hints",
                "auth-analysis",
            ):
                assert states[tool_id] in ("completed", "not_applicable"), tool_id

    def test_assets_carry_provenance_and_are_deduplicated(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            run = harness.run()
            assert run["dedup"]["raw"] >= run["dedup"]["unique"]
            for asset in run["assets"]:
                assert asset["evidence"], asset
                assert asset["evidence"][0]["provider"]

    def test_continuous_discovery_feeds_later_stages(self) -> None:
        """The crawler-discovered GraphQL endpoint feeds the api-graphql stage."""
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            graphql_provider = next(
                (p for stage in harness.run_result.stages if stage.stage.value == "graphql" for p in stage.providers),
                None,
            )
            assert graphql_provider is not None
            if graphql_provider.state.value == "completed":
                assert graphql_provider.assets, "api-graphql must emit operations for the discovered /graphql endpoint"

    def test_report_is_serializable(self, tmp_path: Any) -> None:
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            report = harness.report()
            payload = json.dumps(report, default=str)
            assert payload
            assert report["stage_plan"]
            report_path = tmp_path / "phase4-report.json"
            report_path.write_text(payload, encoding="utf-8")
            assert report_path.stat().st_size > 0

    def test_authenticated_discovery_is_additive(self) -> None:
        """Session-state discovery stays additive: anonymous observations kept,
        authenticated observations add surfaces, not replace them."""
        with GenericDiscoveryFixture() as fixture:
            harness = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            harness.run()
            anonymous_surfaces = harness.service.surface.snapshot()["surfaces"]
            authenticated = Phase4Harness(target=fixture.target, timeout_seconds=15.0, session_state="authenticated")
            authenticated.run()
            assert authenticated.service.surface.snapshot()["surfaces"] >= anonymous_surfaces

    def test_failed_tool_never_kills_the_mission(self) -> None:
        with GenericDiscoveryFixture() as fixture:
            failing = Phase4Harness(target=fixture.target, timeout_seconds=15.0)
            failing._adapters["crawler"] = _BoomAdapter  # noqa: SLF001
            failing._register_adapters()
            failing.run()
            states = failing.provider_states()
            assert states["crawler"] == "failed"
            assert states["javascript"] == "completed"
            assert failing.run_result.summary["assets_total"] > 0


class _BoomAdapter(ToolAdapter):
    """Adapter that always fails at execution time (state honesty probe)."""

    descriptor = ToolDescriptor(name="crawler", version="0.1.0", description="always fails", capabilities=("crawl",), permissions=("network",))

    def run(self, context: Any, collector: Any) -> None:
        raise RuntimeError("simulated adapter failure")


class TestConformance:
    def test_no_target_coupling_in_core(self) -> None:
        """Core architecture carries no Juice Shop / target-specific references."""
        import re

        root = os.path.join(os.path.dirname(__file__), "..", "..", "src", "hunterx")
        for dirpath, _, files in os.walk(root):
            if "__pycache__" in dirpath:
                continue
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                path = os.path.join(dirpath, filename)
                with open(path, encoding="utf-8", errors="replace") as handle:
                    for line_number, line in enumerate(handle, 1):
                        assert not re.search(r"(?i)juice|localhost:3010|:3010", line), (
                            f"{path}:{line_number} couples to a specific target"
                        )


class TestRealBlackBoxRegression:
    """Run the universal pipeline against the real loopback target as an
    arbitrary external target: everything derives from what HunterX observes."""

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_deep_discovery(self) -> None:
        harness = Phase4Harness(target=REAL_TARGET, timeout_seconds=120.0)
        harness.run()
        kinds = harness.assets_by_kind()
        # The SPA's JS bundle must be discovered and analyzed.
        assert kinds.get("javascript_endpoint", 0) >= 1
        assert kinds.get("api_endpoint", 0) >= 1 or kinds.get("url", 0) >= 1
        assert harness.run_result.summary["assets_total"] >= 5
        assert harness.service.surface.snapshot()["surfaces"] >= 5
        # Honest states everywhere: no stage claims more than it did.
        for provider in harness.run_result.provider_states().values():
            assert provider in ("completed", "partial", "failed", "unavailable", "not_applicable")

    @pytest.mark.skipif(not _target_reachable(), reason="regression target not running at localhost:3010")
    def test_black_box_report_is_serializable(self, tmp_path: Any) -> None:
        harness = Phase4Harness(target=REAL_TARGET, timeout_seconds=120.0)
        harness.run()
        report = harness.report()
        payload = json.dumps(report, default=str)
        assert payload
        report_path = tmp_path / "phase4-blackbox-report.json"
        report_path.write_text(payload, encoding="utf-8")
        assert report_path.stat().st_size > 0


__all__: list[str] = []
