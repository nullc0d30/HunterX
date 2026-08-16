# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for Defect 4 — executable shadowing detection.

The live failure: the venv Python ``httpx`` CLI sat earlier in PATH than the
Go ``httpx`` binary HunterX expects, so every httpx execution silently ran the
wrong binary. The launcher now pins ``tools/bin`` before the venv, and
discovery reports same-named competitors so a shadowed provider is a BROKEN
verdict with the shadow documented — never a silent AVAILABLE.
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

from hunterx.tools.readiness.definitions import ToolDefinitionBuilder
from hunterx.tools.readiness.discovery import preferred_tool_directories
from hunterx.tools.readiness.models import ToolReadinessStatus
from tests.framework.readiness import (
    add_to_path,
    fake_executable,
    linux_platform,
    make_discovery,
    tip_with,
)


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore PATH and the preferred-directory variables after every test.

    The active test venv (``sys.prefix``) is neutralized so the preferred
    directory list is fully controlled by the test, not by where pytest runs.
    """
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
    for variable in ("HUNTERX_TOOL_BIN", "HUNTERX_DATA_DIR", "GOBIN", "GOPATH", "VIRTUAL_ENV"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(sys, "prefix", sys.base_prefix)


@pytest.fixture()
def _httpx_definition():
    tip = tip_with(["httpx"])
    platform = linux_platform()
    return ToolDefinitionBuilder(tip, platform).build("httpx")


class TestPreferredDirectoryOrder:
    def test_launcher_order_is_tools_then_go_then_venv(self, tmp_path: pathlib.Path) -> None:
        tools = tmp_path / "tools" / "bin"
        go = tmp_path / "go" / "bin"
        venv = tmp_path / "venv" / "bin"
        for directory in (tools, go, venv):
            directory.mkdir(parents=True)
        os.environ["HUNTERX_TOOL_BIN"] = str(tools)
        os.environ["GOBIN"] = str(go)
        os.environ["VIRTUAL_ENV"] = str(tmp_path / "venv")

        directories = preferred_tool_directories()

        assert len(directories) >= 3
        assert os.path.normpath(directories[0]) == os.path.normpath(str(tools))
        assert os.path.normpath(directories[1]) == os.path.normpath(str(go))
        assert os.path.normpath(directories[2]) == os.path.normpath(str(venv))

    def test_missing_directories_are_omitted(self, tmp_path: pathlib.Path) -> None:
        tools = tmp_path / "tools" / "bin"
        tools.mkdir(parents=True)
        os.environ["HUNTERX_TOOL_BIN"] = str(tools)
        os.environ["GOBIN"] = str(tmp_path / "go" / "bin")

        assert preferred_tool_directories() == (os.path.normpath(str(tools)),)


class TestShadowedExecutable:
    def test_venv_python_cli_shadowing_go_binary_is_broken_with_collision(self, tmp_path: pathlib.Path, _httpx_definition) -> None:  # noqa: ANN001
        # The Python 'httpx' package CLI sits earlier in PATH (the venv). Its
        # version probe output cannot match the declared pattern, so the
        # verdict must be BROKEN — with the preferred Go binary reported as a
        # collision so the shadowing is visible.
        venv_bin = tmp_path / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        fake_executable(venv_bin, "httpx", "Usage: httpx [OPTIONS] URL")
        tools_bin = tmp_path / "tools" / "bin"
        tools_bin.mkdir(parents=True)
        fake_executable(tools_bin, "httpx", "[INF] Current Version: v1.10.0")
        os.environ["VIRTUAL_ENV"] = str(tmp_path / "venv")
        os.environ["HUNTERX_TOOL_BIN"] = str(tools_bin)
        add_to_path(venv_bin)

        verdict = make_discovery().probe(_httpx_definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.BROKEN
        assert "did not match" in verdict.error
        collision_paths = [collision["path"] for collision in verdict.collisions]
        assert collision_paths, "the shadowed provider must be reported as a collision"
        assert os.path.normpath(str(tools_bin / "httpx")) in {
            os.path.normpath(path) for path in collision_paths
        }, "the preferred Go binary must be named as the collision"
        assert any(collision["preferred"] == "true" for collision in verdict.collisions)

    def test_tools_bin_go_binary_first_resolves_available_with_venv_shadow(self, tmp_path: pathlib.Path, _httpx_definition) -> None:  # noqa: ANN001
        # After the launcher fix, tools/bin precedes the venv: the Go binary is
        # the provider (AVAILABLE v1.10.0) and the venv Python CLI is reported
        # as a collision — it exists but must never be executed.
        tools_bin = tmp_path / "tools" / "bin"
        tools_bin.mkdir(parents=True)
        fake_executable(tools_bin, "httpx", "[INF] Current Version: v1.10.0")
        venv_bin = tmp_path / "venv" / "bin"
        venv_bin.mkdir(parents=True)
        fake_executable(venv_bin, "httpx", "Usage: httpx [OPTIONS] URL")
        os.environ["HUNTERX_TOOL_BIN"] = str(tools_bin)
        os.environ["VIRTUAL_ENV"] = str(tmp_path / "venv")
        # add_to_path prepends: the venv must go on first so the Go binary
        # directory ends up EARLIER on PATH (the launcher-pinned order).
        add_to_path(venv_bin)
        add_to_path(tools_bin)

        verdict = make_discovery().probe(_httpx_definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.version == "1.10.0"
        assert os.path.basename(verdict.path) == "httpx"
        collision_paths = [collision["path"] for collision in verdict.collisions]
        assert os.path.normpath(str(venv_bin / "httpx")) in {
            os.path.normpath(path) for path in collision_paths
        }

    def test_unique_provider_has_no_collisions(self, tmp_path: pathlib.Path, _httpx_definition) -> None:  # noqa: ANN001
        only = tmp_path / "tools" / "bin"
        only.mkdir(parents=True)
        fake_executable(only, "httpx", "[INF] Current Version: v1.10.0")
        os.environ["HUNTERX_TOOL_BIN"] = str(only)
        add_to_path(only)

        verdict = make_discovery().probe(_httpx_definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.collisions == ()

    def test_shadowing_detected_in_data_dir_tools_bin(self, tmp_path: pathlib.Path, _httpx_definition) -> None:  # noqa: ANN001
        # Shadowing is also detected when the preferred location is derived
        # from HUNTERX_DATA_DIR (<data>/tools/bin) rather than HUNTERX_TOOL_BIN.
        data_dir = tmp_path / "data"
        tools_bin = data_dir / "tools" / "bin"
        tools_bin.mkdir(parents=True)
        fake_executable(tools_bin, "httpx", "[INF] Current Version: v1.10.0")
        shadow_bin = tmp_path / "shadow" / "bin"
        shadow_bin.mkdir(parents=True)
        fake_executable(shadow_bin, "httpx", "Usage: httpx [OPTIONS] URL")
        os.environ["HUNTERX_DATA_DIR"] = str(data_dir)
        add_to_path(shadow_bin)

        verdict = make_discovery().probe(_httpx_definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.BROKEN
        assert verdict.collisions
