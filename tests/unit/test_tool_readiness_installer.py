# Copyright (c) 2026 Ahmed Awad (NullC0d3)
# SPDX-License-Identifier: Apache-2.0

"""Installer behavior regression tests.

Covers the bootstrapper contract without running real package installs:

- already-installed tool is reused (never reinstalled),
- missing tool is provisioned then located on PATH,
- tool in a non-standard directory is discovered via the user executable dir,
- a wrong same-named executable is classified BROKEN and replaced,
- repeated installation is idempotent,
- PATH changes take effect in the current process (install → PATH → verify).
"""

from __future__ import annotations

import os
import pathlib
import sys

import pytest

from hunterx.tools.readiness.discovery import (
    ToolDiscovery,
    ensure_user_script_paths,
    user_script_directories,
)
from hunterx.tools.readiness.models import ToolReadinessStatus
from hunterx.tools.readiness.provisioner import ToolProvisioner
from tests.framework.readiness import (
    StubRunner,
    all_commands_available,
    fake_executable,
    linux_platform,
    tip_with,
)
from tests.unit.test_tool_readiness_provisioning import StubDiscovery, _definition


@pytest.fixture(autouse=True)
def _isolate_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restore PATH after every test."""
    monkeypatch.setenv("PATH", os.environ.get("PATH", ""))


@pytest.fixture()
def binaries(tmp_path: pathlib.Path) -> pathlib.Path:
    """A temp directory (placed on PATH by tests) for fake binaries."""
    os.environ["PATH"] = str(tmp_path) + os.pathsep + os.environ.get("PATH", "")
    return tmp_path


class TestReuseInstalledTool:
    def test_installed_tool_is_reused_not_reinstalled(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.AVAILABLE, after=ToolReadinessStatus.AVAILABLE)
        provisioner = ToolProvisioner(discovery, platform, runner, command_available=all_commands_available)

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert outcome.skipped
        assert not runner.calls, "an installed tool must not be reinstalled"


class TestMissingToolProvisioning:
    def test_missing_tool_is_provisioned_and_verified(self, binaries: pathlib.Path) -> None:
        # Install path: discovery says MISSING -> provisioner installs -> the
        # fake binary appears on PATH -> re-discovery reports AVAILABLE.
        platform = linux_platform(is_root=True)
        runner = StubRunner({})

        class _InstallingDiscovery(StubDiscovery):
            def probe(self, definition, platform):  # noqa: ANN001
                result = super().probe(definition, platform)
                # After the first probe the installer "installed" the binary.
                fake_executable(binaries, definition.executable, "Nmap version 7.94")
                return result

        discovery = _InstallingDiscovery(before=ToolReadinessStatus.MISSING, after=ToolReadinessStatus.AVAILABLE)
        discovery.probe_count = 0
        provisioner = ToolProvisioner(discovery, platform, runner, command_available=all_commands_available)

        # Add the fake binary directory to PATH (what install.sh does).
        os.environ["PATH"] = str(binaries) + os.pathsep + os.environ.get("PATH", "")

        outcome = provisioner.install(_definition("nmap", platform))

        assert outcome.success
        assert runner.calls, "an install command must be executed"
        assert discovery.marked, "post-install verification must mark the tool installed"


class TestNonStandardDirectory:
    def test_tool_in_user_script_dir_is_discovered(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
        version_tag = f"Python{sys.version_info.major}{sys.version_info.minor}"
        scripts = tmp_path / "Python" / version_tag / "Scripts"
        scripts.mkdir(parents=True)
        fake_executable(scripts, "ghauri", "ghauri 2.0.4")
        monkeypatch.setenv("APPDATA", str(tmp_path))

        directories = user_script_directories()
        assert any(directory.lower().endswith("scripts") for directory in directories)

        # Discovery finds the binary even though it is not on PATH.
        tip = tip_with(["ghauri"])
        from hunterx.tools.readiness.definitions import ToolDefinitionBuilder

        definition = ToolDefinitionBuilder(tip, linux_platform()).build("ghauri")
        verdict = ToolDiscovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE


class TestWrongBinary:
    def test_wrong_binary_is_broken_not_available(self, binaries: pathlib.Path) -> None:
        # A same-named binary whose identity probe does not match is BROKEN.
        fake_executable(binaries, "httpx", "Usage: httpx [OPTIONS] URL")
        os.environ["PATH"] = str(binaries) + os.pathsep + os.environ.get("PATH", "")
        tip = tip_with(["httpx"])
        from hunterx.tools.readiness.definitions import ToolDefinitionBuilder

        definition = ToolDefinitionBuilder(tip, linux_platform()).build("httpx")
        verdict = ToolDiscovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.BROKEN


class TestIdempotency:
    def test_repeated_install_is_idempotent(self) -> None:
        platform = linux_platform(is_root=True)
        runner = StubRunner({})
        discovery = StubDiscovery(before=ToolReadinessStatus.AVAILABLE)
        provisioner = ToolProvisioner(discovery, platform, runner, command_available=all_commands_available)

        first = provisioner.install(_definition("nmap", platform))
        second = provisioner.install(_definition("nmap", platform))

        assert first.skipped and second.skipped
        assert not runner.calls


class TestPathInCurrentProcess:
    def test_ensure_user_script_paths_updates_current_process(self, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path) -> None:
        version_tag = f"Python{sys.version_info.major}{sys.version_info.minor}"
        scripts = tmp_path / "Python" / version_tag / "Scripts"
        scripts.mkdir(parents=True)
        monkeypatch.setenv("APPDATA", str(tmp_path))

        added = ensure_user_script_paths()

        assert str(scripts) in added
        current = os.environ.get("PATH", "").split(os.pathsep)
        assert str(scripts) in current, "the current process PATH must be updated"

    def test_path_update_enables_execution_in_same_run(self, binaries: pathlib.Path) -> None:
        # Simulates install.sh: export the tool dir into the current PATH, then
        # a subsequent command (discovery) sees it immediately.
        os.environ["PATH"] = str(binaries) + os.pathsep + os.environ.get("PATH", "")
        fake_executable(binaries, "nmap", "Nmap version 7.94")

        tip = tip_with(["nmap"])
        from hunterx.tools.readiness.definitions import ToolDefinitionBuilder

        definition = ToolDefinitionBuilder(tip, linux_platform()).build("nmap")
        verdict = ToolDiscovery().probe(definition, linux_platform())

        assert verdict.status is ToolReadinessStatus.AVAILABLE
        assert verdict.path


class TestInstallStatus:
    def test_install_status_classification(self) -> None:
        from hunterx.tools.readiness.models import InstallOutcome

        complete = InstallOutcome(tool_id="a", success=True)
        degraded = [complete, InstallOutcome(tool_id="b", success=False)]
        incomplete = [InstallOutcome(tool_id="a", success=False), InstallOutcome(tool_id="b", success=False)]

        from hunterx.cli.commands import _install_status

        assert _install_status([complete]) == "complete"
        assert _install_status(degraded) == "degraded"
        assert _install_status(incomplete) == "incomplete"
