# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for tool discovery (readiness probing).

Covers available executable, missing executable, broken executable and version
detection, including the wrong-binary false-positive guard.
"""

from __future__ import annotations

import os
import pathlib

import pytest

from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.discovery import ToolDiscovery
from hunterx.tools.readiness.models import ToolReadinessStatus
from tests.framework.readiness import (
    add_to_path,
    fake_executable,
    linux_platform,
    make_discovery,
    tip_with,
)


@pytest.fixture(autouse=True)
def _isolate_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore PATH after every test so fake binaries never leak between tests."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))


@pytest.fixture()
def binaries(tmp_path: pathlib.Path) -> pathlib.Path:
    """A temp directory placed on PATH for fake binaries."""
    add_to_path(tmp_path)
    return tmp_path


def _discovery(binaries: pathlib.Path, *, tool_id: str = "nmap"):
    tip = tip_with([tool_id])
    platform = linux_platform()
    builder = ToolDefinitionBuilder(tip, platform)
    discovery = make_discovery()
    return discovery, builder.build(tool_id), platform


class TestAvailableExecutable:
    def test_available_with_detected_version(self, binaries: pathlib.Path) -> None:
        fake_executable(binaries, "nmap", "Nmap version 7.94 ( https://nmap.org )")
        discovery, definition, platform = _discovery(binaries)

        verdict = discovery.probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.version == "7.94"
        assert verdict.path
        assert os.path.basename(verdict.path).lower().startswith("nmap")

    def test_available_without_version_regex_still_reports_available(self, binaries: pathlib.Path) -> None:
        # 'waybackurls' declares a version probe but no version pattern; any
        # probe output still proves the binary runs.
        fake_executable(binaries, "waybackurls", "just some banner text")
        tip = tip_with(["waybackurls"])
        platform = linux_platform()
        definition = ToolDefinitionBuilder(tip, platform).build("waybackurls")
        assert definition.version_regex == ""

        verdict = make_discovery().probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.AVAILABLE

    def test_available_resolves_absolute_path(self, binaries: pathlib.Path) -> None:
        fake_executable(binaries, "nmap", "Nmap version 7.94")
        discovery, definition, platform = _discovery(binaries)

        verdict = discovery.probe(definition, platform)

        assert os.path.isabs(verdict.path)


class TestMissingExecutable:
    def test_missing_when_not_on_path(self) -> None:
        # A tool id with no manifest spec yields no executable candidate; it is
        # MISSING regardless of anything accidentally present on PATH.
        tip = tip_with(["ghosttool"])
        platform = linux_platform()
        definition = ToolDefinitionBuilder(tip, platform).build("ghosttool")

        verdict = make_discovery().probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.MISSING
        assert verdict.path == ""

    def test_missing_distinguishes_from_broken(self, binaries: pathlib.Path) -> None:
        discovery, definition, platform = _discovery(binaries, tool_id="ghosttool")
        assert discovery.probe(definition, platform).status is ToolReadinessStatus.MISSING

        fake_executable(binaries, "nmap", "Nmap version 7.94")
        nmap_discovery, nmap_definition, _ = _discovery(binaries)
        assert nmap_discovery.probe(nmap_definition, platform).status is ToolReadinessStatus.AVAILABLE


class TestBrokenExecutable:
    def test_wrong_binary_with_mismatched_version_pattern_is_broken(self, binaries: pathlib.Path) -> None:
        # A same-named binary whose version probe output does not match the
        # declared pattern (e.g. the Python 'httpx' package vs ProjectDiscovery
        # httpx) must be BROKEN, not AVAILABLE.
        fake_executable(binaries, "httpx", "Usage: httpx [OPTIONS] URL")
        tip = tip_with(["httpx"])
        platform = linux_platform()
        definition = ToolDefinitionBuilder(tip, platform).build("httpx")
        discovery = make_discovery()

        verdict = discovery.probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.BROKEN
        assert "did not match" in verdict.error


class TestVersionDetection:
    def test_version_extraction_from_stderr(self, binaries: pathlib.Path) -> None:
        fake_executable(binaries, "nmap", "Nmap version 7.80")
        discovery, definition, platform = _discovery(binaries)

        verdict = discovery.probe(definition, platform)

        assert verdict.version == "7.80"

    def test_outdated_when_below_minimum(self, binaries: pathlib.Path) -> None:
        fake_executable(binaries, "nmap", "Nmap version 7.01")
        discovery, definition, platform = _discovery(binaries)
        assert definition.min_version == "7.80"

        verdict = discovery.probe(definition, platform)

        assert verdict.status is ToolReadinessStatus.OUTDATED
        assert verdict.version == "7.01"

    def test_version_detection_captures_probe_command(self, binaries: pathlib.Path) -> None:
        fake_executable(binaries, "nmap", "Nmap version 7.94")
        discovery, definition, platform = _discovery(binaries)

        verdict = discovery.probe(definition, platform)

        assert verdict.detected_command
        assert "--version" in verdict.detected_command


class TestInProcessTools:
    def test_inprocess_with_adapter_is_available(self) -> None:
        from tests.framework.readiness import engine_has, fake_engine

        engine = fake_engine()
        engine_has(engine, "proof-replay", installed=True)
        tip = tip_with(["proof-replay"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("proof-replay")
        assert definition.kind == "inprocess"

        verdict = ToolDiscovery(engine).probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE

    def test_inprocess_without_adapter_is_missing(self) -> None:
        from tests.framework.readiness import fake_engine

        tip = tip_with(["safe-validation"])
        definition = ToolDefinitionBuilder(tip, linux_platform()).build("safe-validation")

        verdict = ToolDiscovery(fake_engine()).probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.MISSING
